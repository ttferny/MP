const express = require('express');
const router = express.Router();

const { evaluateSPFInteractive, parseSPFRecord } = require('../services/spf');
const { lookupARecords, lookupMXRecords, lookupSPFRecord } = require('../services/dns');
const { isValidDomain, isValidIP } = require('../utils/validate');
const logger = require('../utils/logger');

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

router.post('/evaluate', async (req, res) => {
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
});

module.exports = router;
