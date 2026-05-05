/**
 * Aggregate Reporter Service
 * Tracks DMARC evaluation results for audit and analysis
 * Stores in-memory (in production, would use database)
 */

// In-memory storage for reports
let reports = [];
let reportId = 0;

/**
 * Log a DMARC evaluation result
 * @param {Object} evaluation - Result from evaluateDMARC()
 * @param {string} scenario - Scenario key or "raw-header"
 */
const logDMARCResult = (evaluation, scenario = "direct") => {
  const report = {
    id: ++reportId,
    timestamp: new Date().toISOString(),
    scenario,
    status: evaluation.status,
    action: evaluation.action,
    policy: evaluation.policy,
    effectivePolicy: evaluation.effectivePolicy || evaluation.policy,
    riskScore: evaluation.riskScore || 0,
    spfAligned: evaluation.spfAligned,
    dkimAligned: evaluation.dkimAligned,
    fromDomain: evaluation.fromDomain || "unknown",
    aspf: evaluation.aspf,
    adkim: evaluation.adkim,
    sp: evaluation.sp,
    pct: evaluation.pct
  };

  reports.push(report);
  return report;
};

/**
 * Get all reports with optional filtering
 * @param {Object} filters - Optional filters: { status, action, policy, domain, riskScoreMin, riskScoreMax }
 * @returns {Array} Filtered reports
 */
const getReports = (filters = {}) => {
  let results = [...reports];

  if (filters.status) {
    results = results.filter(r => r.status === filters.status);
  }

  if (filters.action) {
    results = results.filter(r => r.action === filters.action);
  }

  if (filters.policy) {
    results = results.filter(r => r.policy === filters.policy);
  }

  if (filters.domain) {
    results = results.filter(r => r.fromDomain === filters.domain);
  }

  if (filters.riskScoreMin !== undefined) {
    results = results.filter(r => r.riskScore >= filters.riskScoreMin);
  }

  if (filters.riskScoreMax !== undefined) {
    results = results.filter(r => r.riskScore <= filters.riskScoreMax);
  }

  return results;
};

/**
 * Get summary statistics for reports
 * @returns {Object} Stats: total, passed, failed, high-risk, by-action, by-policy, by-domain
 */
const getReportSummary = () => {
  if (reports.length === 0) {
    return {
      total: 0,
      passed: 0,
      failed: 0,
      highRisk: 0,
      averageRiskScore: 0,
      byAction: {},
      byPolicy: {},
      byDomain: {},
      byStatus: {}
    };
  }

  const summary = {
    total: reports.length,
    passed: 0,
    failed: 0,
    highRisk: 0,
    averageRiskScore: 0,
    byAction: {},
    byPolicy: {},
    byDomain: {},
    byStatus: {}
  };

  let totalRisk = 0;

  reports.forEach(report => {
    // Count pass/fail
    if (report.status === "pass") {
      summary.passed++;
    } else if (report.status === "fail") {
      summary.failed++;
    }

    // High risk count (score > 70)
    if (report.riskScore > 70) {
      summary.highRisk++;
    }
    totalRisk += report.riskScore;

    // Count by action
    summary.byAction[report.action] = (summary.byAction[report.action] || 0) + 1;

    // Count by policy
    summary.byPolicy[report.policy] = (summary.byPolicy[report.policy] || 0) + 1;

    // Count by domain
    summary.byDomain[report.fromDomain] = (summary.byDomain[report.fromDomain] || 0) + 1;

    // Count by status
    summary.byStatus[report.status] = (summary.byStatus[report.status] || 0) + 1;
  });

  summary.averageRiskScore = Math.round(totalRisk / reports.length);

  return summary;
};

/**
 * Get timeline of reports (for charting)
 * Groups by hour
 * @returns {Array} Timeline data: [{ hour, count, avgRiskScore }, ...]
 */
const getReportTimeline = () => {
  const timeline = {};

  reports.forEach(report => {
    const date = new Date(report.timestamp);
    const hour = date.toISOString().substring(0, 13) + ":00:00Z"; // YYYY-MM-DDTHH:00:00Z

    if (!timeline[hour]) {
      timeline[hour] = { hour, count: 0, totalRisk: 0, passed: 0, failed: 0 };
    }

    timeline[hour].count++;
    timeline[hour].totalRisk += report.riskScore;
    if (report.status === "pass") {
      timeline[hour].passed++;
    } else {
      timeline[hour].failed++;
    }
  });

  // Convert to array and calculate averages
  return Object.values(timeline)
    .map(entry => ({
      ...entry,
      avgRiskScore: Math.round(entry.totalRisk / entry.count)
    }))
    .sort((a, b) => new Date(a.hour) - new Date(b.hour));
};

/**
 * Clear all reports (for testing/reset)
 */
const clearReports = () => {
  reports = [];
  reportId = 0;
};

/**
 * Get a report by ID
 */
const getReportById = (id) => {
  return reports.find(r => r.id === parseInt(id));
};

/**
 * Export reports as CSV for external analysis
 */
const exportReportsAsCSV = () => {
  if (reports.length === 0) {
    return "No reports to export";
  }

  const headers = [
    "ID",
    "Timestamp",
    "Scenario",
    "Status",
    "Action",
    "Policy",
    "Risk Score",
    "From Domain",
    "SPF Aligned",
    "DKIM Aligned"
  ];

  const rows = reports.map(r => [
    r.id,
    r.timestamp,
    r.scenario,
    r.status,
    r.action,
    r.policy,
    r.riskScore,
    r.fromDomain,
    r.spfAligned,
    r.dkimAligned
  ]);

  const csv = [headers, ...rows].map(row => row.join(",")).join("\n");
  return csv;
};

module.exports = {
  logDMARCResult,
  getReports,
  getReportSummary,
  getReportTimeline,
  getReportById,
  clearReports,
  exportReportsAsCSV
};
