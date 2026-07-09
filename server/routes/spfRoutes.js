/**
 * ============================================================
 * spfRoutes.js — SPF REST API Layer
 * ============================================================
 *
 * WHAT THIS FILE DOES (business pitch):
 * -------------------------------------
 * Exposes SPF as three demo-ready product features:
 *   1. Live Auditor   — "Is this IP allowed to send for this domain?"
 *   2. Risk Summary   — plain-English status, risk score, recommendation
 *   3. Policy Simulator — shows why ~all vs -all matters for spoofing
 *
 * WHAT THIS FILE DOES (technical):
 * -------------------------------
 * Mounts at /api/spf in app.js. Delegates evaluation to spf.js and
 * enriches responses with DNS context (A/MX, include chain) plus a
 * commercial summary for the auditor UI.
 *
 * PIPELINE:
 *   Client (spf.html / spf-simulator) → POST /api/spf/check|simulate
 *        → evaluateSPFInteractive() in spf.js
 *        → JSON with result, trace, commercial block
 *
 * DMARC LINK:
 *   SPF results from here feed DMARC alignment when passed through
 *   /api/analyse/header. Alignment requires { status, domain } shape;
 *   this route returns { result, domain } — map before calling dmarc.js.
 */

const express = require('express');
const router = express.Router();

const { evaluateSPFInteractive, parseSPFRecord } = require('../services/spf');
const { lookupARecords, lookupMXRecords, lookupSPFRecord } = require('../services/dns');
const { isValidDomain, isValidIP } = require('../utils/validate');
const logger = require('../utils/logger');

// ─────────────────────────────────────────────
// SIMULATOR SCENARIOS — canned DNS for teaching demos
// PITCH: Each scenario tells a story (CEO fraud, phishing, legit ESP).
// TECH: Mock lookupRecordFn + dnsResolver bypass live DNS so demos
//       work offline and produce predictable outcomes.
// ─────────────────────────────────────────────
const simulatorScenarios = {
  'ceo-fraud': {
    domain: 'company.com',
    recordMap: {
      'company.com': 'v=spf1 ip4:203.0.113.5 include:_spf.partner.com ~all',
      '_spf.partner.com': 'v=spf1 ip4:198.51.100.10 -all',
    },
    aRecords: {
      'company.com': ['203.0.113.5'],
      '_spf.partner.com': ['198.51.100.10'],
    },
    mxRecords: {},
    description: 'A spoofed executive message from an unauthorized source. Softfail warns, hardfail rejects.',
  },
  'phishing': {
    domain: 'dbs.com',
    recordMap: {
      'dbs.com': 'v=spf1 ip4:192.0.2.10 -all',
    },
    aRecords: {
      'dbs.com': ['192.0.2.10'],
    },
    mxRecords: {},
    description: 'A fake bank alert from an attacker IP. Hardfail rejects, softfail flags it.',
  },
  'legit-newsletter': {
    domain: 'news.example.com',
    recordMap: {
      'news.example.com': 'v=spf1 ip4:167.89.0.1 include:_spf.mailer.net -all',
      '_spf.mailer.net': 'v=spf1 ip4:167.89.0.1 -all',
    },
    aRecords: {
      'news.example.com': ['167.89.0.1'],
      '_spf.mailer.net': ['167.89.0.1'],
    },
    mxRecords: {},
    description: 'A legitimate ESP sender with an approved IP for the newsletter stream.',
  },
  'misconfigured': {
    domain: 'vulnerable.org',
    recordMap: {
      'vulnerable.org': 'v=spf1 ?all',
    },
    aRecords: {},
    mxRecords: {},
    description: 'A weak or missing SPF policy. Softfail and hardfail behave differently for unauthorised senders.',
  },
};

/** Resolve a preset scenario by API key (ceo-fraud, phishing, etc.). */
function getSimulatorScenario(key) {
  return simulatorScenarios[key] || null;
}

/** Fallback: match scenario when client sends domain but omits scenarioKey. */
function findSimulatorScenarioByDomain(domain) {
  return Object.values(simulatorScenarios).find((scenario) => scenario.domain === domain) || null;
}

/**
 * Inject fake A/MX answers so evaluateSPFInteractive can run without
 * hitting public DNS — essential for classroom demos with fixed IPs.
 */
function buildSimulatedDnsResolver(scenario) {
  return {
    resolveA: async (targetDomain) => scenario.aRecords[targetDomain] || [],
    resolveMx: async (targetDomain) => scenario.mxRecords[targetDomain] || [],
  };
}

/**
 * Build a narratable step list for the simulator UI.
 * PITCH: Walks the audience through DNS lookup → mechanism check → policy.
 * TECH: Caps trace at 4 steps to keep API payloads readable in the UI.
 */
function buildTimelineSteps(baseline, policyLabel, policyOutcome) {
  const steps = [];

  steps.push({
    title: `Look up SPF record for ${baseline.domain}`,
    sub: baseline.record ? baseline.record : 'No SPF record published in DNS',
    dot: baseline.record ? 'pass' : 'info',
  });

  if (Array.isArray(baseline.trace) && baseline.trace.length > 0) {
    baseline.trace.slice(0, 4).forEach((step, index) => {
      steps.push({
        title: `Check ${step.mechanism || `mechanism ${index + 1}`}`,
        sub: step.detail || `Outcome: ${step.outcome}`,
        dot: step.outcome === 'pass' ? 'pass' : step.outcome === 'softfail' ? 'warn' : step.outcome === 'fail' ? 'fail' : 'info',
      });
    });
  } else {
    steps.push({
      title: 'Evaluate sender IP against policy',
      sub: `No expanded trace was returned; using the final SPF verdict ${baseline.result}.`,
      dot: baseline.result === 'pass' ? 'pass' : baseline.result === 'softfail' ? 'warn' : 'fail',
    });
  }

  steps.push({
    title: `Apply ${policyLabel} policy`,
    sub: policyOutcome.detail,
    dot: policyOutcome.dot,
  });

  return steps;
}

/**
 * Compare soft (~all) vs hard (-all) delivery outcomes for one baseline SPF result.
 * PITCH: Shows executives why "-all" blocks spoofing while "~all" only warns.
 * TECH: unauthorized = baseline.result !== 'pass'; maps to softfail or fail.
 */
function buildSimulationPayload({ domain, attackerIP, baseline, policyResult, policyLabel }) {
  const unauthorized = baseline.result !== 'pass';
  const isSoftPolicy = policyLabel === '~all';
  const result = unauthorized
    ? (isSoftPolicy ? 'softfail' : 'fail')
    : 'pass';

  const steps = buildTimelineSteps(baseline, policyLabel, {
    dot: result === 'pass' ? 'pass' : isSoftPolicy ? 'warn' : 'fail',
    detail: result === 'pass'
      ? `Sender ${attackerIP} is authorized for ${domain}; email is delivered.`
      : isSoftPolicy
        ? 'Suspicious sender flagged by ~all, but mail is still delivered to the recipient.'
        : 'SMTP server rejects the message with a 550 5.7.1 policy violation.',
  });

  return {
    result,
    steps,
    banner: unauthorized && isSoftPolicy
      ? '⚠️ Suspicious Sender: This email failed authentication but was delivered.'
      : null,
    terminalLog: unauthorized && !isSoftPolicy
      ? '550 5.7.1 Sender ID Policy Violation - Message Rejected.'
      : '250 2.0.0 Ok: Message accepted for delivery.',
    clientView: unauthorized && isSoftPolicy
      ? {
          from: `attacker@${domain}`,
          subject: 'Delivery notification',
          status: 'Delivered with warning',
        }
      : null,
  };
}

/**
 * Translate RFC 7208 result strings into business-facing language.
 * PITCH: Gives risk score, impact, and next action without reading DNS syntax.
 * TECH: Normalises result → statusMap / riskMap / recommendationMap / impactMap.
 */
function buildCommercialSummary({ domain, ip, result, record, matchedMechanism, dns, includeRecords }) {
  const normalized = String(result || '').toLowerCase();
  const statusMap = {
    pass: 'Authorized',
    fail: 'Not Authorized',
    softfail: 'Suspicious',
    neutral: 'Inconclusive',
    none: 'Inconclusive',
    temperror: 'Inconclusive',
    permerror: 'Inconclusive',
  };
  const riskMap = {
    pass: 10,
    softfail: 55,
    neutral: 65,
    none: 70,
    temperror: 70,
    permerror: 75,
    fail: 90,
  };
  const recommendationMap = {
    pass: 'Safe to proceed. This email genuinely came from a server authorized for this domain — treat it as legitimate, while still applying normal caution to unexpected requests.',
    softfail: 'Proceed with caution. The domain owner does not fully vouch for this sender. Verify the sender through a known, trusted channel before clicking links, opening attachments, or acting on any request.',
    neutral: 'Do not rely on this email\'s stated identity. SPF gives no clear verdict, so independently confirm the sender through a trusted channel before acting on it.',
    none: 'Treat this email as unverified. The domain publishes no way to confirm its senders, so be skeptical of any links, attachments, or requests and confirm directly with the sender.',
    temperror: 'Hold off on acting. The sender\'s identity could not be checked right now — re-check later or verify the sender through a trusted channel before trusting this email.',
    permerror: 'Treat this email as unverified. The sender\'s identity could not be confirmed, so verify with the sender through a trusted channel before acting on it.',
    fail: 'Do not trust this email. The sender is not authorized to use this domain and it is likely spoofed — do not click links, open attachments, or act on requests, and report it to your security team.',
  };
  const impactMap = {
    pass: 'Low impersonation risk. The sender\'s identity is backed by the domain\'s published policy, so this message is very unlikely to be a spoof.',
    softfail: 'Elevated risk. The domain owner flags this sender as not clearly authorized, so acting on the email could mean engaging with a spoofed message.',
    neutral: 'No assurance of authenticity. Trusting this email could expose you to spoofing or phishing, since its origin cannot be confirmed.',
    none: 'No sender verification is possible. Anyone can impersonate this domain, so this email carries a high phishing risk.',
    temperror: 'Authenticity is temporarily unverifiable. Acting on the email now risks trusting a sender that has not been confirmed.',
    permerror: 'Authenticity cannot be confirmed. You cannot tell a genuine sender from an impersonator, so this email should not be trusted as-is.',
    fail: 'High risk of fraud. This message failed authentication and is likely a spoofing or phishing attempt aimed at the recipient.',
  };

  const aCount = Array.isArray(dns?.aRecords) ? dns.aRecords.length : 0;
  const mxCount = Array.isArray(dns?.mxRecords) ? dns.mxRecords.length : 0;
  const includeCount = includeRecords ? Object.keys(includeRecords).length : 0;

  const highlights = [];
  highlights.push(record ? 'SPF record found' : 'No SPF record found');
  if (matchedMechanism) highlights.push(`Matched mechanism: ${matchedMechanism}`);
  highlights.push(`A records resolved: ${aCount}`);
  highlights.push(`MX records resolved: ${mxCount}`);
  if (includeCount) highlights.push(`Include/redirect domains: ${includeCount}`);

  return {
    status: statusMap[normalized] || 'Inconclusive',
    riskScore: riskMap[normalized] ?? 70,
    recommendation: recommendationMap[normalized] || 'Verify the sender through a trusted channel before acting on this email.',
    businessImpact: impactMap[normalized] || 'The sender\'s authenticity could not be confirmed, so this email should be treated with caution.',
    inputs: { domain, ip },
    highlights,
  };
}

/**
 * POST /api/spf/check and /api/spf/evaluate
 * PITCH: "Type domain + IP → get authorised / not authorised + why."
 * TECH: Parallel DNS fetch (SPF TXT, A, MX) then evaluateSPFInteractive;
 *       expands include/redirect chain for the auditor's include panel.
 */
async function handleEvaluate(req, res) {
  try {
    const { domain, ip } = req.body;
    logger.info(`/api/spf/check called with domain=${domain} ip=${ip}`);

    if (!domain || !ip) {
      return res.status(400).json({ error: 'domain and ip are required.' });
    }

    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: `"${domain}" does not look like a valid domain.` });
    }

    if (!isValidIP(ip)) {
      return res.status(400).json({ error: `"${ip}" does not look like a valid IPv4 address.` });
    }

    const [spfRecord, aRecords, mxRecords] = await Promise.all([
      lookupSPFRecord(domain),
      lookupARecords(domain),
      lookupMXRecords(domain),
    ]);

    const spfResult = await evaluateSPFInteractive(domain, ip);

    const includeRecords = {};
    if (spfRecord) {
      try {
        const mechanisms = parseSPFRecord(spfRecord);
        const includeDomains = mechanisms
          .filter((m) => m.mechName === 'include' || m.mechName === 'redirect')
          .map((m) => m.mechValue)
          .filter(Boolean);

        // Fetch include records with individual error handling
        // so one failure doesn't prevent others from being fetched
        const includeLookups = await Promise.allSettled(
          includeDomains.map(async (includeDomain) => {
            try {
              const record = await lookupSPFRecord(includeDomain);
              return { domain: includeDomain, record: record || '(no SPF record found)', success: true };
            } catch (err) {
              logger.warn(`SPF include lookup failed for ${includeDomain}: ${err.message}`);
              return { domain: includeDomain, record: '(lookup failed)', success: false, error: err.message };
            }
          })
        );

        includeLookups.forEach((result) => {
          if (result.status === 'fulfilled') {
            includeRecords[result.value.domain] = result.value.record;
          } else {
            logger.warn(`SPF include promise rejected: ${result.reason?.message || 'unknown error'}`);
          }
        });
      } catch (err) {
        logger.warn(`SPF include parsing failed: ${err.message}`);
        // Continue without include records - this is non-critical
      }
    }

    const commercialSummary = buildCommercialSummary({
      domain,
      ip,
      result: spfResult.result,
      record: spfRecord,
      matchedMechanism: spfResult.matchedMechanism,
      dns: { aRecords, mxRecords },
      includeRecords,
    });

    return res.json({
      success: true,
      domain,
      ip,
      record: spfRecord,
      result: spfResult.result,
      reason: spfResult.reason,
      matchedMechanism: spfResult.matchedMechanism,
      lookupCount: spfResult.lookupCount || 0,
      dnsLookups: spfResult.lookupCount || 0,
      trace: spfResult.trace || [],
      dns: {
        aRecords,
        mxRecords,
      },
      includeRecords,
      commercial: commercialSummary,
    });
  } catch (err) {
    logger.error(`/api/spf/evaluate error: ${err.message}`);
    return res.status(500).json({ error: 'SPF evaluation failed', details: err.message });
  }
}

router.post('/check', handleEvaluate);
router.post('/evaluate', handleEvaluate);

/**
 * POST /api/spf/simulate
 * PITCH: Side-by-side "~all warns, -all rejects" for spoofing scenarios.
 * TECH: Uses mock DNS when scenarioKey matches; otherwise live evaluation.
 *       Returns { soft, hard } payloads with SMTP terminal strings.
 */
router.post('/simulate', async (req, res) => {
  try {
    const { domain, attackerIP, scenarioKey } = req.body;

    if (!domain || !attackerIP) {
      return res.status(400).json({ error: 'domain and attackerIP are required.' });
    }

    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: `"${domain}" does not look like a valid domain.` });
    }

    if (!isValidIP(attackerIP)) {
      return res.status(400).json({ error: `"${attackerIP}" does not look like a valid IPv4 address.` });
    }

    let scenario = getSimulatorScenario(scenarioKey);
    if (!scenario) {
      scenario = findSimulatorScenarioByDomain(domain);
      if (scenario) {
        logger.info(`/api/spf/simulate fallback scenario by domain ${scenario.domain}`);
      }
    }

    let lookupRecordFn = lookupSPFRecord;
    let dnsResolver = null;
    let effectiveDomain = domain;
    let effectiveAttackerIP = attackerIP;

    if (scenario) {
      dnsResolver = buildSimulatedDnsResolver(scenario);
      lookupRecordFn = async (lookupDomain) => scenario.recordMap[lookupDomain] || null;
      effectiveDomain = scenario.domain || domain;
      effectiveAttackerIP = scenario.attackerIP || attackerIP;
      logger.info(`/api/spf/simulate scenario ${scenarioKey || scenario.domain} -> ${effectiveDomain} ${effectiveAttackerIP}`);
    }

    const baseline = await evaluateSPFInteractive(effectiveDomain, effectiveAttackerIP, lookupRecordFn, dnsResolver);
    const aRecords = scenario ? scenario.aRecords[effectiveDomain] || [] : await lookupARecords(effectiveDomain);
    const mxRecords = scenario ? scenario.mxRecords[effectiveDomain] || [] : await lookupMXRecords(effectiveDomain);
    const spfRecord = baseline.record || (scenario ? scenario.recordMap[effectiveDomain] : await lookupSPFRecord(effectiveDomain));

    const soft = buildSimulationPayload({
      domain,
      attackerIP,
      baseline: { ...baseline, record: spfRecord },
      policyLabel: '~all',
    });

    const hard = buildSimulationPayload({
      domain,
      attackerIP,
      baseline: { ...baseline, record: spfRecord },
      policyLabel: '-all',
    });

    return res.json({
      success: true,
      domain,
      attackerIP,
      scenarioKey: scenarioKey || null,
      record: spfRecord,
      lookupCount: baseline.lookupCount || 0,
      dnsLookups: baseline.lookupCount || 0,
      dns: { aRecords, mxRecords },
      soft,
      hard,
      summary: baseline.result === 'pass'
        ? 'The attacker IP is authorized, so both policies allow delivery.'
        : 'The attacker IP is not authorized, so ~all warns while -all rejects.',
    });
  } catch (err) {
    logger.error(`/api/spf/simulate error: ${err.message}`);
    return res.status(500).json({ error: 'SPF simulation failed', details: err.message });
  }
});

module.exports = router;
