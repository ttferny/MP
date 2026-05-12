// Zircon — DMARC Routes
// All API endpoints for the DMARC policy engine, scenario library,
// aggregate reporting, and DMARC record auditing.
// Base path: /api/dmarc (mounted in app.js)

const express = require('express');
const router  = express.Router();

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


module.exports = router;