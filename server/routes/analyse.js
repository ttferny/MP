/**
 * ============================================================
 * routes/analyse.js — Main API Route Handler
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * The "traffic controller" of the backend.
 * The frontend sends an email header here, and this file passes
 * it through the full authentication pipeline in order:
 *
 *   Step 1 → parser.js      : Extract key fields from raw header
 *   Step 2 → validate.js    : Check parsed data is complete & correct ← NEW (Phase 4)
 *   Step 3 → spf.js         : Check if sending IP is authorised
 *   Step 4 → validate.js    : Check SPF result is well-formed      ← NEW (Phase 4)
 *   Step 5 → dkim.js        : Verify email signature (Ashton)
 *   Step 6 → dmarc.js       : Apply policy, give final verdict (Zircon)
 *   Step 7 → validate.js    : Check full response before sending   ← NEW (Phase 4)
 *
 * ENDPOINTS:
 * ----------
 *   POST /api/analyse/header   — full email authentication pipeline
 *   POST /api/analyse/domain   — DNS record lookup for a domain
 *   POST /api/analyse/scenario — run a pre-built demo scenario
 *
 * HOW IT LINKS:
 * -------------
 *   app.js mounts this file at /api/analyse
 *   validate.js is called at each stage to catch bad data early
 */

const express = require('express');
const router = express.Router();

const { parseEmailHeader }        = require('../services/parser');
const { checkSPF }                = require('../services/spf');
const { verifyDKIM }              = require('../services/dkim');
const { evaluateDMARC }           = require('../services/dmarc');
const {
  validateParsedHeader,
  validateSPFResult,
  validateAnalyseResponse,
}                                  = require('../utils/validate');   // Tiffany Phase 4
const logger                       = require('../utils/logger');

// ──────────────────────────────────────────────────────────────
// ENDPOINT 1: POST /api/analyse/header
// Full authentication pipeline with validation at each step.
// ──────────────────────────────────────────────────────────────
router.post('/header', async (req, res) => {
  try {
    const { rawHeader } = req.body;

    if (!rawHeader || typeof rawHeader !== 'string') {
      return res.status(400).json({ error: 'rawHeader (string) is required.' });
    }

    // ── Step 1: Parse ──────────────────────────────────────
    const parsed = parseEmailHeader(rawHeader);
    logger.info(`Parsed header for domain: ${parsed.fromDomain}`);

    // ── Step 2: Validate parsed output ────────────────────
    // Catches malformed or incomplete headers before going further.
    // Returns HTTP 422 (Unprocessable Entity) if data is invalid.
    const parsedValidation = validateParsedHeader(parsed);
    if (!parsedValidation.valid) {
      return res.status(422).json({
        error: 'Email header validation failed',
        details: parsedValidation.errors,
      });
    }

    // ── Step 3: SPF Check ─────────────────────────────────
    const spfResult = await checkSPF(parsed);

    // ── Step 4: Validate SPF result ───────────────────────
    const spfValidation = validateSPFResult(spfResult);
    if (!spfValidation.valid) {
      return res.status(422).json({
        error: 'SPF result validation failed',
        details: spfValidation.errors,
      });
    }

    // ── Step 5: DKIM Check (Ashton) ───────────────────────
    const dkimResult = await verifyDKIM(parsed);

    // ── Step 6: DMARC Evaluation (Zircon) ─────────────────
    const dmarcResult = await evaluateDMARC(parsed, spfResult, dkimResult);

    // ── Step 7: Validate full response ────────────────────
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

    return res.json(responseObj);

  } catch (err) {
    logger.error(`/header error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────
// ENDPOINT 2: POST /api/analyse/domain
// DNS record lookup — shows SPF/DKIM/DMARC records for a domain.
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
// Runs a pre-built demo scenario (Zircon's scenarioService).
// ──────────────────────────────────────────────────────────────
router.post('/scenario', async (req, res) => {
  try {
    const { scenario } = req.body;

    if (!scenario) {
      return res.status(400).json({ error: 'scenario name is required.' });
    }

    const { runScenario } = require('../services/scenarioService');
    const result = await runScenario(scenario);

    return res.json({ success: true, scenario, result });
  } catch (err) {
    logger.error(`/scenario error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;