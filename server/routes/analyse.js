/**
 * ============================================================
 * routes/analyse.js — Main API Route Handler
 * ============================================================
 */

const express = require('express');
const router  = express.Router();
const scanHistory = require('../utils/store');

const { parseEmailHeader }  = require('../services/parser');
const { checkSPF }          = require('../services/spf');
const { verifyDKIM }        = require('../services/dkim');
const { evaluateDMARC }     = require('../services/dmarc');
const { lookupDMARCRecord } = require('../services/dns');
const { parseDMARCRecord }  = require('../services/dmarcAuditor');
const { checkEmailWithAI }  = require('../services/aiChecker');     
const { getScenario, getAllScenarios } = require('../services/scenarioService');
const {
  validateParsedHeader,
  validateSPFResult,
  validateAnalyseResponse,
} = require('../utils/validate');
const logger = require('../utils/logger');

// ──────────────────────────────────────────────────────────────
// ENDPOINT 1: POST /api/analyse/header
// ──────────────────────────────────────────────────────────────
router.post('/header', async (req, res) => {
  try {
    const { rawHeader, content = '' } = req.body;

    if (!rawHeader || typeof rawHeader !== 'string') {
      return res.status(400).json({ error: 'rawHeader (string) is required.' });
    }

    // Step 1 — Parse
    const parsed = parseEmailHeader(rawHeader);
    logger.info(`Parsed header for domain: ${parsed.fromDomain}`);

    // Step 2 — Validate parsed output
    const parsedValidation = validateParsedHeader(parsed);
    if (!parsedValidation.valid) {
      return res.status(422).json({
        error: 'Email header validation failed',
        details: parsedValidation.errors,
      });
    }

    // Step 3 — SPF Check
    const spfResult = await checkSPF(parsed);

    // Step 4 — Validate SPF result
    const spfValidation = validateSPFResult(spfResult);
    if (!spfValidation.valid) {
      return res.status(422).json({
        error: 'SPF result validation failed',
        details: spfValidation.errors,
      });
    }

    // Step 5 — DKIM Check 
    const dkimResult = await verifyDKIM(parsed);

    // Step 6 — DMARC Evaluation 
    const dmarcRecord = await lookupDMARCRecord(parsed.fromDomain);
    const dmarcTags   = dmarcRecord ? parseDMARCRecord(dmarcRecord) : null;
    const dmarcParsed = dmarcTags
      ? { ...dmarcTags, fromDomain: parsed.fromDomain }
      : { fromDomain: parsed.fromDomain };

    const dmarcResult = await evaluateDMARC(spfResult, dkimResult, dmarcParsed);
    dmarcResult.dmarcRecord = dmarcRecord || null;

    // Step 7 — Validate full response
    const responseObj = {
      success: true,
      parsed,
      results: { spf: spfResult, dkim: dkimResult, dmarc: dmarcResult },
    };

    const responseValidation = validateAnalyseResponse(responseObj);
    if (!responseValidation.valid) {
      return res.status(500).json({
        error: 'Response assembly validation failed',
        details: responseValidation.errors,
      });
    }

    // Step 8 — AI phishing/spoofing analysis 
    // Step 8 — AI phishing/spoofing analysis 
    let aiResult = null;
    try {
        // We wrap this in a try-catch so if the AI crashes, the whole scan doesn't die!
        aiResult = await checkEmailWithAI(parsed, spfResult, dkimResult, dmarcResult, content);
    } catch (aiError) {
        logger.error(`AI Check bypassed: ${aiError.message}`);
    }
    
    // Ensure responseObj always gets something, even if AI failed
    responseObj.ai = aiResult || { error: 'AI unavailable' };

    // --- NEW DASHBOARD SAVING LOGIC WITH FALLBACK ---
    try {
        let threat = 'safe';
        let score = 0;

        // Check if Gemini succeeded
        if (aiResult && (aiResult.threatType || aiResult.classification || aiResult.type)) {
            threat = (aiResult.threatType || aiResult.classification || aiResult.type || 'safe').toLowerCase();
            score = Number(aiResult.riskScore) || 0;
        } else {
            // Fallback rule-based logic if API key is missing
            const dmarcPassed = (dmarcResult.verdict === 'deliver' || dmarcResult.result === 'pass');
            if (!dmarcPassed) {
                threat = 'spoofing';
                score = 75;
            }
        }

        const dashboardData = {
            spf: (spfResult.result === 'pass') ? 'pass' : 'fail',
            dkim: (dkimResult.result === 'pass') ? 'pass' : 'fail',
            dmarc: (dmarcResult.verdict === 'deliver' || dmarcResult.result === 'pass') ? 'pass' : 'fail',
            aiThreat: threat,
            riskScore: score,
            timestamp: new Date()
        };
        scanHistory.push(dashboardData);
    } catch (storeErr) {
        logger.error(`Dashboard Save Error: ${storeErr.message}`);
    }
    // ------------------------------------------------

    return res.json(responseObj);

  } catch (err) {
    logger.error(`/header error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────
// ENDPOINT 2: POST /api/analyse/domain
// ──────────────────────────────────────────────────────────────
router.post('/domain', async (req, res) => {
  try {
    const { domain, dkimSelector = 'default' } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'domain is required.' });
    }

    const { isValidDomain } = require('../utils/validate');
    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: `"${domain}" does not look like a valid domain.` });
    }

    const { lookupSPFRecord, lookupDMARCRecord, lookupDKIMRecord } = require('../services/dns');
    const [spfRecord, dmarcRecord, dkimRecord] = await Promise.all([
      lookupSPFRecord(domain),
      lookupDMARCRecord(domain),
      lookupDKIMRecord(domain, dkimSelector),
    ]);

    return res.json({
      success: true,
      domain,
      records: { spf: spfRecord, dkim: dkimRecord, dmarc: dmarcRecord },
    });
  } catch (err) {
    logger.error(`/domain error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────
// ENDPOINT 3: POST /api/analyse/scenario
// ──────────────────────────────────────────────────────────────
router.post('/scenario', async (req, res) => {
  try {
    const { scenario } = req.body;
    if (!scenario) {
      return res.status(400).json({ error: 'scenario name is required.' });
    }

    const s = getScenario(scenario);
    if (!s) {
      const all = getAllScenarios().map(x => x.key).join(', ');
      return res.status(404).json({ error: `Unknown scenario "${scenario}". Available: ${all}` });
    }

    const parsed = {
      from:           `sender@${s.fromDomain}`,
      fromEmail:      `sender@${s.fromDomain}`,
      fromDomain:     s.fromDomain,
      envelopeFrom:   `sender@${s.spf.domain || s.fromDomain}`,
      envelopeDomain: s.spf.domain || s.fromDomain,
      senderIP:       '203.0.113.10',
      subject:        s.name,
      dkimSignature:  s.dkim.status === 'pass'
        ? { v: '1', a: 'rsa-sha256', d: s.dkim.domain || s.fromDomain, s: 'mail', h: 'from:subject', bh: 'abc', b: 'validsig' }
        : {},
      receivedChain:  [],
      raw:            {},
    };

    const spfResult = {
      result:           s.spf.status,
      reason:           s.spf.status === 'pass'
        ? `Matched mechanism: ip4 on ${s.spf.domain}`
        : `Sender IP not authorised for ${s.spf.domain || s.fromDomain} — matched -all`,
      domain:           s.spf.domain || s.fromDomain,
      ip:               parsed.senderIP,
      record:           s.spf.status === 'pass' ? 'v=spf1 ip4:203.0.113.0/24 -all' : 'v=spf1 ip4:10.0.0.0/8 -all',
      matchedMechanism: s.spf.status === 'pass' ? 'ip4:203.0.113.0/24' : '-all',
    };

    const dkimResult = {
      result:    s.dkim.status,
      reason:    s.dkim.status === 'pass'
        ? `DKIM signature verified for ${s.dkim.domain}`
        : s.dkim.domain
          ? `DKIM domain ${s.dkim.domain} does not align with From domain ${s.fromDomain}`
          : 'No DKIM-Signature header present in email',
      domain:    s.dkim.domain || s.fromDomain,
      selector:  s.dkim.status === 'pass' ? 'mail' : null,
      algorithm: s.dkim.status === 'pass' ? 'rsa-sha256' : null,
      dnsRecord: s.dkim.status === 'pass' ? 'v=DKIM1; k=rsa; p=mockkey' : null,
    };

    const aspfMode  = s.aspf  || 'r';
    const adkimMode = s.adkim || 'r';
    const spfAligned  = spfResult.result  === 'pass' && checkAlignment(s.fromDomain, spfResult.domain,  aspfMode);
    const dkimAligned = dkimResult.result === 'pass' && checkAlignment(s.fromDomain, dkimResult.domain, adkimMode);
    const dmarcPasses = spfAligned || dkimAligned;
    const policy      = s.defaultPolicy || 'none';
    const effectivePolicy = s.sp && s.fromDomain.includes('.') ? s.sp : policy;

    let verdict, verdictReason;
    if (dmarcPasses) {
      verdict       = 'deliver';
      verdictReason = `DMARC passed. ${spfAligned ? 'SPF' : 'DKIM'} alignment verified with From domain '${s.fromDomain}'. Email delivered.`;
    } else {
      verdict = effectivePolicy === 'reject'     ? 'reject'
              : effectivePolicy === 'quarantine' ? 'quarantine'
              : 'none';
      const why = [];
      if (!spfAligned)  why.push(`SPF ${spfResult.result === 'pass' ? 'passed but domain misaligned' : 'failed'}`);
      if (!dkimAligned) why.push(`DKIM ${dkimResult.result === 'pass' ? 'passed but domain misaligned' : 'failed or absent'}`);
      verdictReason = `DMARC failed for '${s.fromDomain}'. ${why.join('; ')}. `
        + (verdict === 'reject'     ? 'Email REJECTED by DMARC policy.'
          : verdict === 'quarantine' ? 'Email QUARANTINED — moved to spam.'
          : 'No enforcement (p=none) — email delivered despite failure.');
    }

    const dmarcResult = {
      verdict,
      policy: effectivePolicy,
      reason: verdictReason,
      spfAligned,
      dkimAligned,
      dmarcRecord: `v=DMARC1; p=${policy}${s.sp ? `; sp=${s.sp}` : ''}${aspfMode !== 'r' ? `; aspf=${aspfMode}` : ''}${adkimMode !== 'r' ? `; adkim=${adkimMode}` : ''}`,
      tags:        { p: policy, aspf: aspfMode, adkim: adkimMode },
      explanation: s.explanation,
      attackDescription: s.attack,
    };

    const aiResult = await checkEmailWithAI(parsed, spfResult, dkimResult, dmarcResult);

    // --- NEW DASHBOARD SAVING LOGIC FOR SCENARIOS WITH FALLBACK ---
    try {
        let threat = 'safe';
        let score = 0;

        if (aiResult && (aiResult.threatType || aiResult.classification || aiResult.type)) {
            threat = (aiResult.threatType || aiResult.classification || aiResult.type || 'safe').toLowerCase();
            score = Number(aiResult.riskScore) || 0;
        } else {
            const dmarcPassed = (dmarcResult.verdict === 'deliver' || dmarcResult.result === 'pass');
            if (!dmarcPassed) {
                threat = 'spoofing';
                score = 75;
            }
        }

        const dashboardData = {
            spf: (spfResult.result === 'pass') ? 'pass' : 'fail',
            dkim: (dkimResult.result === 'pass') ? 'pass' : 'fail',
            dmarc: (dmarcResult.verdict === 'deliver' || dmarcResult.result === 'pass') ? 'pass' : 'fail',
            aiThreat: threat,
            riskScore: score,
            timestamp: new Date()
        };
        scanHistory.push(dashboardData);
    } catch (storeErr) {
        logger.error(`Dashboard Save Error: ${storeErr.message}`);
    }
    // --------------------------------------------------------------

    return res.json({
      success: true,
      scenario,
      scenarioMeta: { name: s.name, icon: s.icon, desc: s.desc, attack: s.attack },
      result: {
        parsed,
        results: { spf: spfResult, dkim: dkimResult, dmarc: dmarcResult },
        ai: aiResult,
      },
    });

  } catch (err) {
    logger.error(`/scenario error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

// DMARC alignment helper
function checkAlignment(fromDomain, checkDomain, mode = 'r') {
  if (!fromDomain || !checkDomain) return false;
  const from  = fromDomain.toLowerCase();
  const check = checkDomain.toLowerCase();
  if (mode === 's') return from === check;
  const rootFrom  = from.split('.').slice(-2).join('.');
  const rootCheck = check.split('.').slice(-2).join('.');
  return rootFrom === rootCheck;
}

module.exports = router;