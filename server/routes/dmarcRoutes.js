// Zircon — DMARC Routes
// All API endpoints for the DMARC policy engine, scenario library,
// aggregate reporting, and DMARC record auditing.
// Base path: /api/dmarc (mounted in app.js)

const { lookupDMARCRecord } = require('../services/dns'); 
const express = require('express');
const router  = express.Router();
const multer = require('multer');

const { evaluateDMARC }                = require('../services/dmarc');
const { getAllScenarios, getScenario } = require('../services/scenarioService');
const { auditDMARC }                   = require('../services/dmarcAuditor');
const {
  logDMARCResult,
  getReports,
  getReportSummary,
  getReportTimeline,
  getReportById,
  clearReports,
  exportReportsAsCSV
} = require('../services/aggregateReporter');
const { parseDMARCReport } = require('../services/dmarcXmlParser');
const { analyzeDMARCReport } = require('../services/dmarcReportAnalyzer');

// Configure multer for file uploads
const upload = multer({ 
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/xml' || file.originalname.endsWith('.xml')) {
      cb(null, true);
    } else {
      cb(new Error('Only XML files are allowed'));
    }
  }
});


// ─────────────────────────────────────────────────────────────
// SECTION 1 — DIRECT EVALUATION
// Accepts raw SPF, DKIM, and DMARC inputs and runs the engine
// ─────────────────────────────────────────────────────────────

// POST /api/dmarc/evaluate
// Evaluates SPF + DKIM alignment against a DMARC policy
// Body: { spf, dkim, parsed, log? }
//   spf    — { status: "pass"|"fail", domain: "..." }
//   dkim   — { status: "pass"|"fail", domain: "..." }
//   parsed — { policy, fromDomain, pct?, aspf?, adkim?, sp? }
//   log    — if true, records result in aggregate reporter
router.post('/evaluate', (req, res) => {
  const { spf, dkim, parsed, log = false } = req.body;

  // Apply defaults for alignment modes if not provided
  const enhancedParsed = {
    ...parsed,
    aspf:  parsed?.aspf  || "r",
    adkim: parsed?.adkim || "r"
  };

  const result = evaluateDMARC(spf, dkim, enhancedParsed);

  if (log) {
    logDMARCResult(result, "direct-eval");
  }

  res.json(result);
});


// ─────────────────────────────────────────────────────────────
// SECTION 2 — SCENARIO LIBRARY
// Pre-built attack and authentication scenarios stored in
// scenarioService.js — each runs through the DMARC engine
// ─────────────────────────────────────────────────────────────

// GET /api/dmarc/scenarios
// Returns a list of all available scenario keys, names, and icons
router.get('/scenarios', (req, res) => {
  res.json(getAllScenarios());
});

// POST /api/dmarc/scenarios/:key
// Runs a named scenario through the DMARC policy engine
// Body (all optional): { policy, aspf, adkim, sp, log }
//   Overrides the scenario's default values if provided
//   log — if true, records result in aggregate reporter
router.post('/scenarios/:key', (req, res) => {
  const scenario = getScenario(req.params.key);

  if (!scenario) {
    return res.status(404).json({ error: `Scenario "${req.params.key}" not found` });
  }

  // Build parsed DMARC object — use request body overrides or fall back to scenario defaults
  const parsed = {
    policy:     req.body.policy  || scenario.defaultPolicy,
    aspf:       req.body.aspf    || scenario.aspf  || "r",
    adkim:      req.body.adkim   || scenario.adkim || "r",
    sp:         req.body.sp      || scenario.sp    || null,
    pct:        100,
    fromDomain: scenario.fromDomain
  };

  const result = evaluateDMARC(scenario.spf, scenario.dkim, parsed);

  if (req.body.log) {
    logDMARCResult(result, req.params.key);
  }

  res.json({
    ...result,
    scenarioName: scenario.name,
    explanation:  scenario.explanation
  });
});


// ─────────────────────────────────────────────────────────────
// SECTION 3 — DMARC RECORD AUDITOR
// Analyses a raw DMARC TXT record string and grades the
// domain's DMARC configuration against security best practices.
// DNS lookup is handled by Ashton's DNS module — this route
// only receives the record and evaluates it.
// ─────────────────────────────────────────────────────────────

// POST /api/dmarc/audit
// Grades a DMARC record against security best practices
// Body: { domain, dmarcRecord }
//   domain      — the domain being audited (e.g. "dbs.com.sg")
//   dmarcRecord — raw DMARC TXT record string from Ashton's DNS module
//                 e.g. "v=DMARC1; p=reject; rua=mailto:dmarc@dbs.com.sg; pct=100"
//                 pass null or omit if no DMARC record exists for the domain
// Returns: { domain, score, grade, issues[], recommendations[], dmarc{} }
router.post('/audit', (req, res) => {
  const { domain, dmarcRecord } = req.body;

  if (!domain) {
    return res.status(400).json({ error: "domain is required" });
  }

  const result = auditDMARC(dmarcRecord, domain);
  res.json(result);
});

// GET /api/dmarc/audit/:domain
// Fetches the real DMARC record from DNS using Ashton's dns.js module
// then runs it through the DMARC auditor automatically
// No request body needed — just pass the domain in the URL
// e.g. GET /api/dmarc/audit/google.com
router.get('/audit/:domain', async (req, res) => {
  try {
    const dmarcRecord = await lookupDMARCRecord(req.params.domain);
    const result = auditDMARC(dmarcRecord, req.params.domain);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─────────────────────────────────────────────────────────────
// SECTION 4 — AGGREGATE REPORTS
// Logs and retrieves DMARC evaluation history.
// Every evaluate/scenario call with log=true is stored here
// in-memory via aggregateReporter.js
// ─────────────────────────────────────────────────────────────

// GET /api/dmarc/reports
// Retrieve all recorded evaluations with optional filtering
// Query params: status, action, policy, domain, riskScoreMin, riskScoreMax
router.get('/reports', (req, res) => {
  const filters = {};

  if (req.query.status)       filters.status       = req.query.status;
  if (req.query.action)       filters.action       = req.query.action;
  if (req.query.policy)       filters.policy       = req.query.policy;
  if (req.query.domain)       filters.domain       = req.query.domain;
  if (req.query.riskScoreMin) filters.riskScoreMin = parseInt(req.query.riskScoreMin);
  if (req.query.riskScoreMax) filters.riskScoreMax = parseInt(req.query.riskScoreMax);

  const reports = getReports(filters);
  res.json({ count: reports.length, reports });
});

// GET /api/dmarc/reports/summary
// Returns aggregated statistics — totals, pass/fail counts,
// average risk score, breakdown by action, policy, and domain
router.get('/reports/summary', (req, res) => {
  res.json(getReportSummary());
});

// GET /api/dmarc/reports/timeline
// Returns evaluation history grouped by hour — used for charting
router.get('/reports/timeline', (req, res) => {
  res.json(getReportTimeline());
});

// GET /api/dmarc/reports/export/csv
// Downloads all stored reports as a CSV file
router.get('/reports/export/csv', (req, res) => {
  const csv = exportReportsAsCSV();
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', 'attachment; filename="dmarc-reports.csv"');
  res.send(csv);
});

// GET /api/dmarc/reports/:id
// Retrieve a single report entry by its numeric ID
router.get('/reports/:id', (req, res) => {
  const report = getReportById(req.params.id);
  if (!report) {
    return res.status(404).json({ error: `Report ${req.params.id} not found` });
  }
  res.json(report);
});

// DELETE /api/dmarc/reports
// Clears all stored reports — for testing and demo resets only
router.delete('/reports', (req, res) => {
  clearReports();
  res.json({ message: "All reports cleared" });
});

// POST /api/dmarc/smtp/send-test
// Triggers a test email to be sent to the SMTP receiver on port 2525
// Body: { type } — "legitimate", "spoof", "ceo-fraud", "spf-misalign"
router.post('/smtp/send-test', async (req, res) => {
  const nodemailer = require('nodemailer');
  const type = req.body.type || 'legitimate';

  const transporter = nodemailer.createTransport({
    host: 'localhost', port: 2525, secure: false,
    tls: { rejectUnauthorized: false }
  });

  const emails = {
    'legitimate':   { from: 'noreply@google.com',    subject: 'Legitimate Email Test',      auth: 'spf=pass smtp.mailfrom=google.com; dkim=pass header.d=google.com',      returnPath: 'noreply@google.com' },
    'spoof':        { from: 'security@dbs.com.sg',   subject: 'Basic Spoof Test',           auth: 'spf=fail smtp.mailfrom=evil.com; dkim=fail',                            returnPath: 'bounce@evil.com' },
    'ceo-fraud':    { from: 'ceo@company.com',       subject: 'CEO Fraud Test',             auth: 'spf=pass smtp.mailfrom=ceo-company.com; dkim=none',                     returnPath: 'ceo@ceo-company.com' },
    'spf-misalign': { from: 'support@dbs.com.sg', subject: 'SPF Misalign Test',          auth: 'spf=pass smtp.mailfrom=evil.com; dkim=fail',                            returnPath: 'bounce@evil.com' },
  };

  const email = emails[type] || emails['legitimate'];

  try {
    await transporter.sendMail({
      from: email.from, to: 'test@localhost',
      subject: email.subject, text: 'Test email for DMARC evaluation',
      headers: {
        'Authentication-Results': email.auth,
        'Return-Path': `<${email.returnPath}>`
      }
    });
    res.json({ message: `Test email sent: ${email.subject}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ─────────────────────────────────────────────────────────────
// SECTION 5 — DMARC XML REPORT ANALYZER (NEW)
// Uploads and analyzes DMARC XML aggregate reports
// ─────────────────────────────────────────────────────────────

// POST /api/dmarc/upload
// Uploads a DMARC XML report and parses it
// Expects: multipart/form-data with file field containing XML
router.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const xmlContent = req.file.buffer.toString('utf-8');
    const parsed = await parseDMARCReport(xmlContent);

    res.json({
      success: true,
      data: parsed
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// POST /api/dmarc/analyze
// Analyzes a parsed DMARC report and returns insights
// Body: { parsed DMARC report from /upload or similar }
router.post('/analyze', (req, res) => {
  try {
    const dmarcReport = req.body;

    if (!dmarcReport || !dmarcReport.records) {
      return res.status(400).json({
        error: 'Invalid DMARC report format. Expected parsed report with records array.'
      });
    }

    const analysis = analyzeDMARCReport(dmarcReport);

    res.json({
      success: true,
      analysis
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});


// ─────────────────────────────────────────────────────────────
// SECTION 6 — DNS PROPAGATION CHECKER
// Queries multiple public DNS resolvers to check whether a
// DMARC record has propagated worldwide.
// Uses Node's built-in dns module with custom resolver addresses.
// ─────────────────────────────────────────────────────────────

// GET /api/dmarc/propagation/:domain
// Checks DMARC record propagation across Google, Cloudflare, OpenDNS, and Quad9
router.get('/propagation/:domain', async (req, res) => {
  const domain = req.params.domain;
  const { Resolver } = require('dns').promises;

  // Four major public DNS resolvers
  const resolvers = [
    { name: 'Google',     ip: '8.8.8.8',       flag: '🇺🇸' },
    { name: 'Cloudflare', ip: '1.1.1.1',       flag: '🌐' },
    { name: 'OpenDNS',    ip: '208.67.222.222', flag: '🇺🇸' },
    { name: 'Quad9',      ip: '9.9.9.9',        flag: '🇨🇭' },
  ];

  // Query each resolver in parallel with a 5 second timeout
  const results = await Promise.all(resolvers.map(async (r) => {
    const resolver = new Resolver();
    resolver.setServers([r.ip]);

    try {
      const records = await Promise.race([
        resolver.resolveTxt(`_dmarc.${domain}`),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
      ]);

      // Find the DMARC record among all TXT records
      const dmarcRecord = records.flat().find(rec => rec.startsWith('v=DMARC1')) || null;

      return {
        resolver:  r.name,
        ip:        r.ip,
        flag:      r.flag,
        status:    dmarcRecord ? 'found' : 'not_found',
        record:    dmarcRecord,
        error:     null,
      };
    } catch (err) {
      return {
        resolver:  r.name,
        ip:        r.ip,
        flag:      r.flag,
        status:    err.message === 'timeout' ? 'timeout' : 'not_found',
        record:    null,
        error:     err.message === 'timeout' ? 'Request timed out' : null,
      };
    }
  }));

  // Check consistency — do all resolvers return the same record?
  const foundRecords  = results.filter(r => r.record).map(r => r.record);
  const uniqueRecords = [...new Set(foundRecords)];
  const allAgree      = uniqueRecords.length <= 1;
  const propagated    = results.filter(r => r.status === 'found').length;

  res.json({
    domain,
    checkedAt:    new Date().toISOString(),
    results,
    summary: {
      total:       resolvers.length,
      found:       propagated,
      notFound:    results.filter(r => r.status === 'not_found').length,
      timedOut:    results.filter(r => r.status === 'timeout').length,
      allAgree,
      uniqueRecords,
      propagationStatus:
        propagated === 0              ? 'NOT_PROPAGATED' :
        propagated < resolvers.length ? 'PARTIALLY_PROPAGATED' :
        allAgree                      ? 'FULLY_PROPAGATED' : 'INCONSISTENT',
    }
  });
});


// ─────────────────────────────────────────────────────────────
// SECTION 7 — DOMAIN PROTECTION ANALYSER
// Fetches real SPF, DKIM, and DMARC records for a domain
// and simulates what would happen if someone tried to spoof it.
// Uses Ashton's DNS module for all lookups.
// ─────────────────────────────────────────────────────────────

// GET /api/dmarc/protect/:domain
// Returns real DNS records and simulates a spoof attack outcome
router.get('/protect/:domain', async (req, res) => {
  const domain = req.params.domain;
  const { lookupSPFRecord, lookupDKIMRecord, lookupMXRecords } = require('../services/dns');
  const { parseDMARCRecord } = require('../services/dmarcAuditor');

  try {
    // Fetch all records in parallel with timeouts
    const withTimeout = (promise, ms = 4000) => Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms))
    ]);

    const [spfRaw, dmarcRaw, dkimRaw, mxRecords] = await Promise.all([
      withTimeout(lookupSPFRecord(domain)).catch(() => null),
      withTimeout(lookupDMARCRecord(domain)).catch(() => null),
      withTimeout(lookupDKIMRecord(domain)).catch(() => null),
      withTimeout(lookupMXRecords(domain)).catch(() => [])
    ]);

    // Parse DMARC record
    const dmarc = parseDMARCRecord(dmarcRaw);

    // Evaluate SPF strength
    const spfStrength =
      !spfRaw                       ? 'missing' :
      spfRaw.includes('-all')       ? 'strong' :
      spfRaw.includes('~all')       ? 'weak' :
      spfRaw.includes('+all')       ? 'dangerous' : 'configured';

    // Simulate a spoof attack — attacker sends from evil.com, From: domain
    const spoofSpf  = { status: 'fail', domain: 'evil.com' };
    const spoofDkim = { status: 'fail', domain: '' };
    const dmarcParsed = dmarc ? {
      policy:     dmarc.policy || 'none',
      fromDomain: domain,
      pct:        dmarc.pct || 100,
      aspf:       dmarc.aspf || 'r',
      adkim:      dmarc.adkim || 'r',
      sp:         dmarc.sp || null,
    } : {
      policy: 'none', fromDomain: domain, pct: 100, aspf: 'r', adkim: 'r', sp: null
    };

    const spoofResult = evaluateDMARC(spoofSpf, spoofDkim, dmarcParsed);

    // Simulate a legitimate email — same domain, SPF and DKIM pass
    const legitSpf  = { status: 'pass', domain: domain };
    const legitDkim = { status: 'pass', domain: domain };
    const legitResult = evaluateDMARC(legitSpf, legitDkim, dmarcParsed);

    // Build step by step flow for both simulations
    const buildFlow = (spf, dkim, label) => {
      const spfAligned  = spf.status === 'pass' && spf.domain === domain;
      const dkimAligned = dkim.status === 'pass' && dkim.domain === domain;
      const dmarcPass   = spfAligned || dkimAligned;
      return {
        label,
        spf:  { ...spf,  aligned: spfAligned },
        dkim: { ...dkim, aligned: dkimAligned },
        dmarcPass,
        result: evaluateDMARC(spf, dkim, dmarcParsed)
      };
    };

    res.json({
      domain,
      records: {
        spf:  { raw: spfRaw,  strength: spfStrength },
        dkim: { raw: dkimRaw, found: !!dkimRaw },
        dmarc: { raw: dmarcRaw, parsed: dmarc },
        mx:   mxRecords
      },
      simulations: {
        spoof: buildFlow(spoofSpf, spoofDkim, 'Spoof attack'),
        legit: buildFlow(
          { status: 'pass', domain },
          { status: 'pass', domain },
          'Legitimate email'
        )
      },
      checkedAt: new Date().toISOString()
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;