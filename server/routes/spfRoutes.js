const express = require('express');
const router = express.Router();

const { evaluateSPFInteractive, parseSPFRecord } = require('../services/spf');
const { lookupARecords, lookupMXRecords, lookupSPFRecord } = require('../services/dns');
const { isValidDomain, isValidIP } = require('../utils/validate');
const logger = require('../utils/logger');

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

function getSimulatorScenario(key) {
  return simulatorScenarios[key] || null;
}

function findSimulatorScenarioByDomain(domain) {
  return Object.values(simulatorScenarios).find((scenario) => scenario.domain === domain) || null;
}

function buildSimulatedDnsResolver(scenario) {
  return {
    resolveA: async (targetDomain) => scenario.aRecords[targetDomain] || [],
    resolveMx: async (targetDomain) => scenario.mxRecords[targetDomain] || [],
  };
}

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
  // Recommendation — what the person who RECEIVED this email should do next,
  // based on the SPF verdict. Framed for the reader/recipient, not the domain admin.
  const recommendationMap = {
    pass: 'Sender is verified as authorized for this domain. You can treat the sender identity as genuine, but still judge the message content on its own merits before acting.',
    softfail: 'Treat this email with caution — the sender was not fully authorized. Do not act on any request, click links, or open attachments until you confirm it with the sender through a known, trusted channel.',
    neutral: 'The sender identity cannot be confirmed from SPF. Do not rely on the "From" address; verify the sender independently before trusting any request in this email.',
    none: 'This domain publishes no SPF policy, so the sender cannot be verified. Be cautious and confirm the sender through a trusted channel before acting on the email.',
    temperror: 'The sender could not be verified right now due to a temporary lookup problem. Do not assume the email is safe — hold off on sensitive actions and confirm with the sender directly if it looks urgent.',
    permerror: 'The sending domain\'s SPF setup is broken, so the sender cannot be verified. Treat the email as unverified and confirm the sender independently before acting.',
    fail: 'Do not trust this email. The sending server is not authorized by the domain it claims to be from, which is a strong sign of spoofing or phishing. Do not click links, open attachments, or reply — report it to your IT or security team.',
  };
  // Business impact — the risk to the RECIPIENT of acting on this specific email.
  const impactMap = {
    pass: 'Low risk. Acting on this email is unlikely to expose you to sender impersonation.',
    softfail: 'Elevated risk. The email may be impersonating the sender; acting on it without verifying could lead to fraud or a compromised account.',
    neutral: 'Uncertain risk. You cannot tell whether the sender is genuine, so any request in this email could be fraudulent.',
    none: 'Elevated risk. With no SPF protection on this domain, anyone can impersonate the sender, so requests in this email should be treated as unverified.',
    temperror: 'Unknown risk. Sender authenticity is unconfirmed, so treating this email as trusted right now could be premature.',
    permerror: 'Unknown risk. The sender\'s authentication is unreliable, so the email\'s legitimacy cannot be assured.',
    fail: 'High risk. Acting on this email could expose you to fraud, phishing, or malware from someone impersonating the sender.',
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
    recommendation: recommendationMap[normalized] || 'Sender could not be verified. Treat this email as unverified and confirm the sender through a trusted channel before acting.',
    businessImpact: impactMap[normalized] || 'Unknown risk. Sender authenticity is unconfirmed, so treat any request in this email with caution.',
    inputs: { domain, ip },
    highlights,
  };
}

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

        const includeLookups = await Promise.all(
          includeDomains.map(async (includeDomain) => ({
            domain: includeDomain,
            record: await lookupSPFRecord(includeDomain),
          }))
        );

        includeLookups.forEach((entry) => {
          includeRecords[entry.domain] = entry.record || '(no SPF record found)';
        });
      } catch (err) {
        logger.warn(`SPF include parsing failed: ${err.message}`);
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
