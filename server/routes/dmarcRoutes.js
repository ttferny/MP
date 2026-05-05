const express = require('express');
const router  = express.Router();

const { evaluateDMARC }               = require('../services/dmarc');
const { getAllScenarios, getScenario } = require('../services/scenarioService');
const { parseEmailForDMARC }          = require('../services/parser');
const { logDMARCResult, getReports, getReportSummary, getReportTimeline, getReportById, clearReports, exportReportsAsCSV } = require('../services/aggregateReporter');

// POST /api/dmarc/evaluate
// Direct evaluation — accepts raw SPF, DKIM, and parsed DMARC inputs
// Optional: aspf, adkim (defaults to relaxed "r")
// Optional: log=true to record in aggregate reports
router.post('/evaluate', (req, res) => {
  const { spf, dkim, parsed, log = false } = req.body;
  
  // Ensure aspf/adkim defaults are set
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


// GET /api/dmarc/scenarios
// Returns list of all available scenario keys and names
router.get('/scenarios', (req, res) => {
  res.json(getAllScenarios());
});

// POST /api/dmarc/scenarios/:key
// Runs a named scenario through the DMARC engine
// Accepts optional { policy, aspf, adkim, sp, log } in body to override scenario defaults
router.post('/scenarios/:key', (req, res) => {
  const scenario = getScenario(req.params.key);

  if (!scenario) {
    return res.status(404).json({ error: `Scenario "${req.params.key}" not found` });
  }

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

// GET /api/dmarc/reports
// Retrieve all reports with optional filtering
// Query params: status, action, policy, domain, riskScoreMin, riskScoreMax
router.get('/reports', (req, res) => {
  const filters = {};
  
  if (req.query.status) filters.status = req.query.status;
  if (req.query.action) filters.action = req.query.action;
  if (req.query.policy) filters.policy = req.query.policy;
  if (req.query.domain) filters.domain = req.query.domain;
  if (req.query.riskScoreMin) filters.riskScoreMin = parseInt(req.query.riskScoreMin);
  if (req.query.riskScoreMax) filters.riskScoreMax = parseInt(req.query.riskScoreMax);

  const reports = getReports(filters);
  res.json({
    count: reports.length,
    reports
  });
});

// GET /api/dmarc/reports/summary
// Get aggregated statistics from all reports
router.get('/reports/summary', (req, res) => {
  const summary = getReportSummary();
  res.json(summary);
});

// GET /api/dmarc/reports/timeline
// Get timeline of reports (for charting)
router.get('/reports/timeline', (req, res) => {
  const timeline = getReportTimeline();
  res.json(timeline);
});

// GET /api/dmarc/reports/:id
// Get a single report by ID
router.get('/reports/:id', (req, res) => {
  const report = getReportById(req.params.id);
  if (!report) {
    return res.status(404).json({ error: `Report ${req.params.id} not found` });
  }
  res.json(report);
});

// GET /api/dmarc/reports/export/csv
// Export all reports as CSV
router.get('/reports/export/csv', (req, res) => {
  const csv = exportReportsAsCSV();
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', 'attachment; filename="dmarc-reports.csv"');
  res.send(csv);
});

// DELETE /api/dmarc/reports
// Clear all reports (testing only)
router.delete('/reports', (req, res) => {
  clearReports();
  res.json({ message: "All reports cleared" });
});

module.exports = router;