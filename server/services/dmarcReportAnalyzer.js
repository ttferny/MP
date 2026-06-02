/**
 * DMARC Report Analyzer Service
 * Analyzes parsed DMARC records to extract insights:
 * - Mail servers (IPs/domains)
 * - SPF/DKIM pass/fail statistics
 * - Suspicious IPs and failure patterns
 * - Spoofing detection
 * - Risk scoring
 */

/**
 * Analyze DMARC report data
 * @param {Object} dmarcReport - Parsed DMARC report from dmarcXmlParser
 * @returns {Object} Analysis results with insights and recommendations
 */
function analyzeDMARCReport(dmarcReport) {
  const { records, policy, metadata } = dmarcReport;

  // Initialize analysis
  const mailServers = extractMailServers(records);
  const authStats = calculateAuthStats(records);
  const suspiciousIPs = identifySuspiciousIPs(records, mailServers);
  const spoofingIndicators = detectSpoofingAttempts(records);
  const riskAssessment = assessRisk(records, spoofingIndicators, policy);

  return {
    summary: {
      reportDate: metadata.dateRange,
      domain: policy.domain,
      organization: metadata.orgName,
      totalRecords: dmarcReport.totalRecords,
      totalEmails: records.reduce((sum, r) => sum + r.count, 0),
      policy: {
        mode: policy.p,
        alignment: {
          spf: policy.aspf,
          dkim: policy.adkim
        },
        enforcement: `${policy.pct}%`
      }
    },
    mailServers: {
      count: mailServers.unique.length,
      servers: mailServers.detailed,
      authenticated: {
        spf: mailServers.authenticated.spf,
        dkim: mailServers.authenticated.dkim,
        both: mailServers.authenticated.both
      }
    },
    authenticationStats: authStats,
    suspiciousActivity: {
      suspiciousIPs: suspiciousIPs.suspicious,
      failurePatterns: suspiciousIPs.patterns,
      totalSuspiciousEmails: suspiciousIPs.totalCount
    },
    spoofingDetection: spoofingIndicators,
    riskAssessment: riskAssessment,
    recommendations: generateRecommendations(authStats, spoofingIndicators, policy, mailServers)
  };
}

/**
 * Extract and categorize mail servers
 */
function extractMailServers(records) {
  const servers = new Map();
  const authenticatedSpf = new Set();
  const authenticatedDkim = new Set();
  const authenticatedBoth = new Set();

  records.forEach(record => {
    const ip = record.sourceIp;
    const headerFrom = record.headerFrom;

    if (!servers.has(ip)) {
      servers.set(ip, {
        ip,
        domain: resolveDomainFromIP(ip),
        emailCount: 0,
        headerFrom: new Set(),
        spfStatus: new Map(),
        dkimStatus: new Map(),
        alignment: {
          spf: [],
          dkim: []
        }
      });
    }

    const server = servers.get(ip);
    server.emailCount += record.count;
    server.headerFrom.add(headerFrom);

    // Track SPF results
    if (record.spf) {
      const spfDomain = record.spf.domain;
      server.spfStatus.set(spfDomain, record.spf.result);
      if (record.spf.result === 'pass') {
        authenticatedSpf.add(ip);
      }
    }

    // Track DKIM results
    if (Array.isArray(record.dkim)) {
      record.dkim.forEach(sig => {
        server.dkimStatus.set(sig.domain, sig.result);
        if (sig.result === 'pass') {
          authenticatedDkim.add(ip);
        }
      });
    }

    // Track alignment
    if (record.policyEvaluated.spfAlign === 'pass') {
      server.alignment.spf.push(record.envelopeFrom);
    }
    if (record.policyEvaluated.dkimAlign === 'pass') {
      server.alignment.dkim.push(headerFrom);
    }
  });

  // Combine authenticated checks
  authenticatedBoth.forEach(ip => {
    if (authenticatedSpf.has(ip) && authenticatedDkim.has(ip)) {
      authenticatedBoth.add(ip);
    }
  });

  // Convert to array and sort by email count
  const detailed = Array.from(servers.values())
    .map(server => ({
      ip: server.ip,
      domain: server.domain,
      emailCount: server.emailCount,
      senders: Array.from(server.headerFrom),
      spf: {
        domains: Array.from(server.spfStatus.keys()),
        results: Object.fromEntries(server.spfStatus)
      },
      dkim: {
        domains: Array.from(server.dkimStatus.keys()),
        results: Object.fromEntries(server.dkimStatus)
      },
      alignment: server.alignment
    }))
    .sort((a, b) => b.emailCount - a.emailCount);

  return {
    unique: Array.from(servers.keys()),
    detailed,
    authenticated: {
      spf: Array.from(authenticatedSpf),
      dkim: Array.from(authenticatedDkim),
      both: Array.from(authenticatedBoth)
    }
  };
}

/**
 * Calculate authentication pass/fail statistics
 */
function calculateAuthStats(records) {
  let spfPass = 0;
  let spfFail = 0;
  let dkimPass = 0;
  let dkimFail = 0;
  let dkimNone = 0;
  let alignedEmails = 0;
  let failedEmails = 0;

  records.forEach(record => {
    const count = record.count;

    // SPF stats
    if (record.spf?.result === 'pass') {
      spfPass += count;
    } else {
      spfFail += count;
    }

    // DKIM stats
    if (Array.isArray(record.dkim)) {
      const dkimResults = record.dkim.map(d => d.result);
      if (dkimResults.includes('pass')) {
        dkimPass += count;
      } else if (dkimResults.includes('none')) {
        dkimNone += count;
      } else {
        dkimFail += count;
      }
    } else {
      dkimNone += count;
    }

    // Alignment
    if (
      record.policyEvaluated.spfAlign === 'pass' &&
      record.policyEvaluated.dkimAlign === 'pass'
    ) {
      alignedEmails += count;
    } else if (
      record.policyEvaluated.spfAlign === 'fail' &&
      record.policyEvaluated.dkimAlign === 'fail'
    ) {
      failedEmails += count;
    }
  });

  const total = spfPass + spfFail;

  return {
    spf: {
      pass: spfPass,
      fail: spfFail,
      passRate: total > 0 ? ((spfPass / total) * 100).toFixed(2) : 0
    },
    dkim: {
      pass: dkimPass,
      fail: dkimFail,
      none: dkimNone,
      passRate: total > 0 ? ((dkimPass / total) * 100).toFixed(2) : 0
    },
    alignment: {
      aligned: alignedEmails,
      failed: failedEmails,
      alignmentRate: total > 0 ? ((alignedEmails / total) * 100).toFixed(2) : 0
    }
  };
}

/**
 * Identify suspicious IPs based on failure patterns
 */
function identifySuspiciousIPs(records, mailServers) {
  const suspicious = [];
  const patterns = {};

  mailServers.detailed.forEach(server => {
    let riskScore = 0;
    const reasons = [];

    // Check SPF failures
    const spfFails = Object.entries(server.spf.results)
      .filter(([_, result]) => result === 'fail')
      .length;
    if (spfFails > 0) {
      riskScore += 20;
      reasons.push(`SPF fails for ${spfFails} domain(s)`);
    }

    // Check DKIM failures
    const dkimFails = Object.entries(server.dkim.results)
      .filter(([_, result]) => result === 'fail')
      .length;
    if (dkimFails > 0) {
      riskScore += 20;
      reasons.push(`DKIM fails for ${dkimFails} domain(s)`);
    }

    // Check multiple senders from same IP
    if (server.senders.length > 3) {
      riskScore += 15;
      reasons.push(`Multiple senders (${server.senders.length}) from same IP`);
    }

    // Check for unaligned emails
    const totalEmails = server.emailCount;
    const aligned = server.alignment.spf.length + server.alignment.dkim.length;
    if (aligned === 0 && totalEmails > 0) {
      riskScore += 30;
      reasons.push('No authentication alignment');
    }

    if (riskScore >= 30) {
      suspicious.push({
        ip: server.ip,
        domain: server.domain,
        emailCount: server.emailCount,
        riskScore,
        reasons,
        senders: server.senders
      });

      patterns[server.ip] = {
        failureType: reasons.join('; '),
        severity: riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW'
      };
    }
  });

  return {
    suspicious: suspicious.sort((a, b) => b.riskScore - a.riskScore),
    patterns,
    totalCount: suspicious.reduce((sum, ip) => sum + ip.emailCount, 0)
  };
}

/**
 * Detect spoofing attempts
 */
function detectSpoofingAttempts(records) {
  const spoofingIndicators = {
    detected: false,
    confidence: 0,
    indicators: [],
    affectedEmails: 0
  };

  let suspiciousCount = 0;

  records.forEach(record => {
    const headerFrom = record.headerFrom;
    const envelopeFrom = record.envelopeFrom;

    // Mismatch between From header and envelope
    if (headerFrom !== envelopeFrom && !headerFrom.includes(envelopeFrom)) {
      spoofingIndicators.indicators.push({
        type: 'header-envelope-mismatch',
        headerFrom,
        envelopeFrom,
        count: record.count
      });
      suspiciousCount += record.count;
    }

    // Both SPF and DKIM failed
    if (
      record.spf?.result === 'fail' &&
      (Array.isArray(record.dkim)
        ? record.dkim.every(d => d.result === 'fail')
        : record.dkim?.result === 'fail')
    ) {
      spoofingIndicators.indicators.push({
        type: 'auth-double-fail',
        ip: record.sourceIp,
        headerFrom,
        count: record.count
      });
      suspiciousCount += record.count;
    }

    // Policy disposition is reject
    if (record.disposition === 'reject') {
      spoofingIndicators.indicators.push({
        type: 'policy-reject',
        ip: record.sourceIp,
        headerFrom,
        count: record.count
      });
    }
  });

  if (suspiciousCount > 0) {
    spoofingIndicators.detected = true;
    spoofingIndicators.confidence = Math.min(100, Math.floor((suspiciousCount / records.reduce((sum, r) => sum + r.count, 0)) * 100));
    spoofingIndicators.affectedEmails = suspiciousCount;
  }

  return spoofingIndicators;
}

/**
 * Assess overall risk
 */
function assessRisk(records, spoofingIndicators, policy) {
  let riskScore = 0;
  const factors = [];

  // Policy enforcement level
  if (policy.p === 'none') {
    riskScore += 20;
    factors.push('DMARC policy is in monitoring-only mode (p=none)');
  } else if (policy.p === 'quarantine') {
    riskScore += 10;
    factors.push('DMARC policy is quarantine (less strict than reject)');
  }

  // Partial enforcement
  if (policy.pct < 100) {
    riskScore += 10;
    factors.push(`Only ${policy.pct}% of emails subject to policy`);
  }

  // Spoofing detected
  if (spoofingIndicators.detected) {
    riskScore += Math.floor(spoofingIndicators.confidence / 2);
    factors.push(`Spoofing indicators detected (${spoofingIndicators.confidence}% confidence)`);
  }

  // Relaxed alignment
  if (policy.aspf === 'r' || policy.adkim === 'r') {
    riskScore += 5;
    factors.push('Relaxed alignment mode used (allows subdomains)');
  }

  return {
    overallRiskScore: Math.min(100, riskScore),
    riskLevel: riskScore >= 70 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW',
    factors
  };
}

/**
 * Generate actionable recommendations
 */
function generateRecommendations(authStats, spoofingIndicators, policy, mailServers) {
  const recommendations = [];

  // SPF recommendations
  if (parseFloat(authStats.spf.passRate) < 90) {
    recommendations.push({
      priority: 'HIGH',
      category: 'SPF',
      issue: 'SPF authentication pass rate below 90%',
      action: 'Review SPF records to ensure all legitimate mail servers are authorized',
      impact: 'Reduces email deliverability and increases spoofing risk'
    });
  }

  // DKIM recommendations
  if (parseFloat(authStats.dkim.passRate) < 80) {
    recommendations.push({
      priority: 'HIGH',
      category: 'DKIM',
      issue: 'DKIM authentication pass rate below 80%',
      action: 'Verify DKIM selector records are properly configured on mail servers',
      impact: 'Weak email authentication creates spoofing opportunities'
    });
  }

  // Policy recommendations
  if (policy.p === 'none') {
    recommendations.push({
      priority: 'MEDIUM',
      category: 'Policy',
      issue: 'DMARC policy is in monitoring-only mode',
      action: 'Consider upgrading to p=quarantine or p=reject after validation',
      impact: 'Current policy does not prevent spoofed emails'
    });
  }

  // Spoofing recommendations
  if (spoofingIndicators.detected) {
    recommendations.push({
      priority: 'CRITICAL',
      category: 'Security',
      issue: `Spoofing attempts detected (${spoofingIndicators.confidence}% confidence)`,
      action: 'Review suspicious IPs and consider adding them to block lists',
      impact: 'Active spoofing attempts targeting your domain'
    });
  }

  // Suspicious IP recommendations
  const highRiskIPs = mailServers.detailed.filter(s => {
    const aligned = s.alignment.spf.length + s.alignment.dkim.length;
    return aligned === 0 && s.emailCount > 0;
  });

  if (highRiskIPs.length > 0) {
    recommendations.push({
      priority: 'HIGH',
      category: 'Authentication',
      issue: `${highRiskIPs.length} mail server(s) with no authentication alignment`,
      action: 'Investigate these servers and either authorize them or block them',
      impact: 'Unauthorized servers can cause email delivery issues and security risks'
    });
  }

  return recommendations;
}

/**
 * Resolve domain from IP (placeholder)
 */
function resolveDomainFromIP(ip) {
  // In production, this would do reverse DNS lookup
  return ip;
}

module.exports = {
  analyzeDMARCReport
};
