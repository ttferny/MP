const express = require('express');
const router = express.Router();

const { evaluateSPFInteractive, parseSPFRecord } = require('../services/spf');
const { lookupARecords, lookupMXRecords, lookupSPFRecord } = require('../services/dns');
const { isValidDomain, isValidIP } = require('../utils/validate');
const logger = require('../utils/logger');

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
  const recommendationMap = {
    pass: 'Maintain current SPF policy and monitor for drift.',
    softfail: 'Review sending infrastructure and tighten to -all once verified.',
    neutral: 'Publish a definitive SPF policy (ideally -all) for enforcement.',
    none: 'Publish an SPF record to prevent unauthorized senders.',
    temperror: 'Retry evaluation; if persistent, check DNS availability.',
    permerror: 'Fix SPF syntax errors to enable reliable enforcement.',
    fail: 'Block this sender IP; investigate for spoofing attempts.',
  };
  const impactMap = {
    pass: 'Low spoofing exposure for this sender path.',
    softfail: 'Elevated exposure; spoofing may still slip through.',
    neutral: 'Unclear protection; mail systems may treat spoofing as acceptable.',
    none: 'High exposure; no SPF-based protection in place.',
    temperror: 'Temporary blind spot; authentication cannot be verified.',
    permerror: 'Policy unusable; authentication decisions are unreliable.',
    fail: 'High risk event; sender is not authorized by SPF.',
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
    recommendation: recommendationMap[normalized] || 'Review SPF configuration and retry.',
    businessImpact: impactMap[normalized] || 'Authentication result requires review.',
    inputs: { domain, ip },
    highlights,
  };
}

async function handleEvaluate(req, res) {
  try {
    const { domain, ip } = req.body;

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
    const { domain, attackerIP } = req.body;

    if (!domain || !attackerIP) {
      return res.status(400).json({ error: 'domain and attackerIP are required.' });
    }

    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: `"${domain}" does not look like a valid domain.` });
    }

    if (!isValidIP(attackerIP)) {
      return res.status(400).json({ error: `"${attackerIP}" does not look like a valid IPv4 address.` });
    }

    const baseline = await evaluateSPFInteractive(domain, attackerIP);
    const aRecords = await lookupARecords(domain);
    const mxRecords = await lookupMXRecords(domain);
    const spfRecord = baseline.record || (await lookupSPFRecord(domain));

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
