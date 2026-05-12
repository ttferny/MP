/**
 * ============================================================
 * routes/analyse.js — Main API Route Handler
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * Think of this as the "traffic controller" of the backend.
 * The frontend sends an email header (or domain) here,
 * and this file passes it through the authentication pipeline:
 *
 *   Step 1 → parser.js   : Read and extract data from the email header
 *   Step 2 → spf.js      : Check if the sending IP is authorised
 *   Step 3 → dkim.js     : Check if the email content was tampered with
 *   Step 4 → dmarc.js    : Apply the domain's policy and give final verdict
 *
 * ENDPOINTS:
 * ----------
 *   POST /api/analyse/header   — Analyse raw email headers (main demo)
 *   POST /api/analyse/domain   — Look up DNS records for a domain
 *   POST /api/analyse/scenario — Run a pre-built demo scenario
 *
 * HOW IT LINKS:
 * -------------
 *   app.js mounts this file at /api/analyse
 *   This file calls: parser.js → spf.js → dkim.js → dmarc.js
 *   Results are returned to the frontend (script.js / dmarc_ui.js)
 */

const express = require('express');
const router = express.Router();

// Import all service modules — each handles one protocol
const { parseEmailHeader } = require('../services/parser');      // Tiffany
const { checkSPF }         = require('../services/spf');         // Tiffany
const { verifyDKIM }       = require('../services/dkim');        // Ashton
const { evaluateDMARC }    = require('../services/dmarc');       // Zircon
const logger               = require('../utils/logger');

// ──────────────────────────────────────────────────────────────
// ENDPOINT 1: POST /api/analyse/header
// PURPOSE   : The main demo — full authentication pipeline
// INPUT     : { rawHeader: string }  — paste of raw email headers
// OUTPUT    : { parsed, results: { spf, dkim, dmarc } }
//
// This is what the frontend calls when a user submits an email header.
// ──────────────────────────────────────────────────────────────
router.post('/header', async (req, res) => {
  try {
    const { rawHeader } = req.body;

    // Validate input — must be a non-empty string
    if (!rawHeader || typeof rawHeader !== 'string') {
      return res.status(400).json({ error: 'rawHeader (string) is required.' });
    }

    // ── Step 1: Parse ──────────────────────────────────────
    // parser.js reads the raw header text and extracts:
    //   fromDomain, envelopeDomain, senderIP, dkimSignature, etc.
    // These values are used by SPF, DKIM, and DMARC below.
    const parsed = parseEmailHeader(rawHeader);
    logger.info(`Parsed header for domain: ${parsed.fromDomain}`);

    // ── Step 2: SPF Check ─────────────────────────────────
    // spf.js asks: "Is this IP allowed to send for this domain?"
    // Uses: parsed.senderIP + parsed.envelopeDomain
    const spfResult = await checkSPF(parsed);

    // ── Step 3: DKIM Check ────────────────────────────────
    // dkim.js asks: "Was this email signed and is the signature valid?"
    // Uses: parsed.dkimSignature + parsed.fromDomain
    const dkimResult = await verifyDKIM(parsed);

    // ── Step 4: DMARC Evaluation ──────────────────────────
    // dmarc.js takes both SPF and DKIM results and applies the domain's
    // policy: deliver / quarantine / reject
    const dmarcResult = await evaluateDMARC(parsed, spfResult, dkimResult);

    // Return all results to the frontend
    return res.json({
      success: true,
      parsed,
      results: {
        spf:   spfResult,
        dkim:  dkimResult,
        dmarc: dmarcResult,
      },
    });
  } catch (err) {
    logger.error(`/header error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────
// ENDPOINT 2: POST /api/analyse/domain
// PURPOSE   : DNS record lookup — shows what SPF/DKIM/DMARC records
//             a domain has published (Ashton's DNS checker module)
// INPUT     : { domain: string, dkimSelector?: string }
// OUTPUT    : { domain, records: { spf, dkim, dmarc } }
// ──────────────────────────────────────────────────────────────
router.post('/domain', async (req, res) => {
  try {
    const { domain, dkimSelector = 'default' } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'domain is required.' });
    }

    // dns.js handles all DNS lookups
    const { lookupSPFRecord, lookupDMARCRecord, lookupDKIMRecord } = require('../services/dns');

    // Run all three lookups at the same time (parallel, faster)
    const [spfRecord, dmarcRecord, dkimRecord] = await Promise.all([
      lookupSPFRecord(domain),
      lookupDMARCRecord(domain),
      lookupDKIMRecord(domain, dkimSelector),
    ]);

    return res.json({
      success: true,
      domain,
      records: {
        spf:  spfRecord,
        dkim: dkimRecord,
        dmarc: dmarcRecord,
      },
    });
  } catch (err) {
    logger.error(`/domain error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────
// ENDPOINT 3: POST /api/analyse/scenario
// PURPOSE   : Run a named pre-built demo scenario
//             e.g. "valid_email", "spoofed_spf", "spoofed_dkim"
//             Used to demonstrate pass/fail cases in the UI
// INPUT     : { scenario: string }
// OUTPUT    : { scenario, result }
// ──────────────────────────────────────────────────────────────
router.post('/scenario', async (req, res) => {
  try {
    const { scenario } = req.body;

    if (!scenario) {
      return res.status(400).json({ error: 'scenario name is required.' });
    }

    // scenarioService.js (Zircon) holds the pre-built scenario definitions
    const { runScenario } = require('../services/scenarioService');
    const result = await runScenario(scenario);

    return res.json({ success: true, scenario, result });
  } catch (err) {
    logger.error(`/scenario error: ${err.message}`);
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;