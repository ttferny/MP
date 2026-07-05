/**
 * ============================================================
 * spfRoutes.js — HTTP API layer for the SPF feature
 * ============================================================
 *
 * WHAT THIS FILE DOES (business view):
 * ------------------------------------
 * This is the "front desk" between the browser UI (spf.js, spf-simulator.js)
 * and the SPF trust engine (services/spf.js). It exposes three endpoints:
 *   POST /api/spf/check    → run a live SPF audit for a real domain + IP
 *   POST /api/spf/evaluate → alias of /check (same handler)
 *   POST /api/spf/simulate → run a safe "what-if" attack scenario for demos
 *
 * WHY IT MATTERS (pitch note):
 * ----------------------------
 * The route layer is where a raw protocol result becomes a *decision a
 * business can act on*. It validates input, calls the evaluator, then wraps
 * the technical verdict in a "commercial summary" (status, risk score,
 * recommendation, business impact) that non-technical stakeholders understand.
 *
 * TECHNICAL DEPENDENCIES:
 * -----------------------
 *   services/spf.js  → the actual SPF evaluation logic (RFC 7208)
 *   services/dns.js  → live DNS lookups (SPF TXT, A, MX records)
 *   utils/validate.js → input guards so bad data never reaches the engine
 */

const express = require('express');
const router = express.Router();

// SPF evaluation engine + record parser (the "brains" of the feature).
const { evaluateSPFInteractive, parseSPFRecord } = require('../services/spf');
// Live DNS helpers — turn a domain name into its published records.
const { lookupARecords, lookupMXRecords, lookupSPFRecord } = require('../services/dns');
// Input validation — reject malformed domains/IPs before spending DNS calls.
const { isValidDomain, isValidIP } = require('../utils/validate');
const logger = require('../utils/logger');

// ─────────────────────────────────────────────────────────────
// SIMULATOR SCENARIOS (demo dataset)
// ─────────────────────────────────────────────────────────────
// Pre-scripted, real-world-style stories used by /api/spf/simulate.
// These let a presenter show dangerous outcomes (CEO fraud, phishing)
// WITHOUT touching live DNS or real infrastructure. Each scenario ships
// its own fake DNS "universe" (recordMap / aRecords / mxRecords) so the
// evaluator behaves deterministically during a pitch.
const simulatorScenarios = {
  // Executive impersonation: an unauthorised server pretending to be the CEO.
  'ceo-fraud': {
    domain: 'company.com',
    // recordMap = the SPF TXT records this fake DNS would return per domain.
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
  // Fake bank alert — the classic phishing pattern with a strict -all policy.
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
  // Legitimate marketing mail sent through an approved Email Service Provider.
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
  // Weak policy (?all) — shows how a misconfigured domain offers no protection.
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

// Look up a scenario by its key (e.g. the tab the user clicked in the UI).
function getSimulatorScenario(key) {
  return simulatorScenarios[key] || null;
}

// Fallback: if no key was sent, try to match the typed domain to a scenario.
function findSimulatorScenarioByDomain(domain) {
  return Object.values(simulatorScenarios).find((scenario) => scenario.domain === domain) || null;
}

// Build a fake DNS resolver backed by the scenario's canned records.
// This is dependency injection: the SAME evaluator runs, but its DNS calls
// are answered from the scenario instead of the live internet — safe for demos.
function buildSimulatedDnsResolver(scenario) {
  return {
    resolveA: async (targetDomain) => scenario.aRecords[targetDomain] || [],
    resolveMx: async (targetDomain) => scenario.mxRecords[targetDomain] || [],
  };
}

// ─────────────────────────────────────────────────────────────
// buildTimelineSteps — turn an evaluation into a narratable story
// ─────────────────────────────────────────────────────────────
// Converts the technical trace into an ordered list of "what happened"
// cards the UI animates. This is the visual backbone of a live demo:
// lookup record → check each mechanism → apply the policy verdict.
function buildTimelineSteps(baseline, policyLabel, policyOutcome) {
  const steps = [];

  // Step 1: did the domain even publish an SPF record?
  steps.push({
    title: `Look up SPF record for ${baseline.domain}`,
    sub: baseline.record ? baseline.record : 'No SPF record published in DNS',
    dot: baseline.record ? 'pass' : 'info',
  });

  // Steps 2..n: replay up to the first four mechanism checks from the trace.
  if (Array.isArray(baseline.trace) && baseline.trace.length > 0) {
    baseline.trace.slice(0, 4).forEach((step, index) => {
      steps.push({
        title: `Check ${step.mechanism || `mechanism ${index + 1}`}`,
        sub: step.detail || `Outcome: ${step.outcome}`,
        dot: step.outcome === 'pass' ? 'pass' : step.outcome === 'softfail' ? 'warn' : step.outcome === 'fail' ? 'fail' : 'info',
      });
    });
  } else {
    // No detailed trace available — fall back to summarising the final verdict.
    steps.push({
      title: 'Evaluate sender IP against policy',
      sub: `No expanded trace was returned; using the final SPF verdict ${baseline.result}.`,
      dot: baseline.result === 'pass' ? 'pass' : baseline.result === 'softfail' ? 'warn' : 'fail',
    });
  }

  // Final step: apply the policy (~all vs -all) and show the business outcome.
  steps.push({
    title: `Apply ${policyLabel} policy`,
    sub: policyOutcome.detail,
    dot: policyOutcome.dot,
  });

  return steps;
}

// ─────────────────────────────────────────────────────────────
// buildSimulationPayload — model ONE policy choice (~all or -all)
// ─────────────────────────────────────────────────────────────
// The simulator's core teaching point: the SAME unauthorised sender is
// handled differently depending on the domain's chosen enforcement level.
// Soft (~all) still delivers with a warning; hard (-all) rejects outright.
function buildSimulationPayload({ domain, attackerIP, baseline, policyResult, policyLabel }) {
  // "unauthorized" = the sender IP did not earn a pass from the SPF engine.
  const unauthorized = baseline.result !== 'pass';
  const isSoftPolicy = policyLabel === '~all';
  // Map (authorised?, policy strength) → the final SPF verdict shown to users.
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
    // Inbox-style warning banner — only shown for the "delivered but risky" case.
    banner: unauthorized && isSoftPolicy
      ? '⚠️ Suspicious Sender: This email failed authentication but was delivered.'
      : null,
    // Simulated SMTP server response line for the terminal view in the UI.
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

// ─────────────────────────────────────────────────────────────
// buildCommercialSummary — translate a protocol result into business language
// ─────────────────────────────────────────────────────────────
// This is the "pitch translator". The SPF engine returns terse RFC verdicts
// (pass/fail/softfail/neutral/none/temperror/permerror); this function maps
// each one to: a human status, a 0–100 risk score, a recommended action, and
// the business impact — the exact framing needed for stakeholder slides.
function buildCommercialSummary({ domain, ip, result, record, matchedMechanism, dns, includeRecords }) {
  const normalized = String(result || '').toLowerCase();
  // Technical verdict → plain-English status label.
  const statusMap = {
    pass: 'Authorized',
    fail: 'Not Authorized',
    softfail: 'Suspicious',
    neutral: 'Inconclusive',
    none: 'Inconclusive',
    temperror: 'Inconclusive',
    permerror: 'Inconclusive',
  };
  // Technical verdict → risk score (higher = more spoofing/deliverability risk).
  const riskMap = {
    pass: 10,
    softfail: 55,
    neutral: 65,
    none: 70,
    temperror: 70,
    permerror: 75,
    fail: 90,
  };
  // Technical verdict → the single most useful next action to take.
  const recommendationMap = {
    pass: 'Maintain current SPF policy and monitor for drift.',
    softfail: 'Review sending infrastructure and tighten to -all once verified.',
    neutral: 'Publish a definitive SPF policy (ideally -all) for enforcement.',
    none: 'Publish an SPF record to prevent unauthorized senders.',
    temperror: 'Retry evaluation; if persistent, check DNS availability.',
    permerror: 'Fix SPF syntax errors to enable reliable enforcement.',
    fail: 'Block this sender IP; investigate for spoofing attempts.',
  };
  // Technical verdict → the real-world consequence, in business terms.
  const impactMap = {
    pass: 'Low spoofing exposure for this sender path.',
    softfail: 'Elevated exposure; spoofing may still slip through.',
    neutral: 'Unclear protection; mail systems may treat spoofing as acceptable.',
    none: 'High exposure; no SPF-based protection in place.',
    temperror: 'Temporary blind spot; authentication cannot be verified.',
    permerror: 'Policy unusable; authentication decisions are unreliable.',
    fail: 'High risk event; sender is not authorized by SPF.',
  };

  // Quantify the domain's sending footprint — evidence behind the summary.
  const aCount = Array.isArray(dns?.aRecords) ? dns.aRecords.length : 0;
  const mxCount = Array.isArray(dns?.mxRecords) ? dns.mxRecords.length : 0;
  const includeCount = includeRecords ? Object.keys(includeRecords).length : 0;

  // Bullet points that back up the verdict with concrete findings.
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

// ─────────────────────────────────────────────────────────────
// handleEvaluate — the live SPF audit endpoint (/check and /evaluate)
// ─────────────────────────────────────────────────────────────
// End-to-end flow: validate input → run the live SPF evaluation →
// resolve supporting DNS records → package a technical + commercial report.
async function handleEvaluate(req, res) {
  try {
    const { domain, ip } = req.body;
    logger.info(`/api/spf/check called with domain=${domain} ip=${ip}`);

    // Guard clauses: fail fast (HTTP 400) on missing or malformed input so we
    // never waste live DNS lookups — and never leak confusing engine errors.
    if (!domain || !ip) {
      return res.status(400).json({ error: 'domain and ip are required.' });
    }

    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: `"${domain}" does not look like a valid domain.` });
    }

    if (!isValidIP(ip)) {
      return res.status(400).json({ error: `"${ip}" does not look like a valid IPv4 address.` });
    }

    // Fetch the three DNS record types in parallel for speed (one round-trip).
    const [spfRecord, aRecords, mxRecords] = await Promise.all([
      lookupSPFRecord(domain),
      lookupARecords(domain),
      lookupMXRecords(domain),
    ]);

    // Run the interactive evaluation — returns the verdict PLUS a full trace.
    const spfResult = await evaluateSPFInteractive(domain, ip);

    // Expand any include:/redirect: chains so the UI can show delegated trust —
    // i.e. which third-party providers this domain also relies on.
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

    // Turn the raw verdict into the stakeholder-facing summary (status/risk/etc).
    const commercialSummary = buildCommercialSummary({
      domain,
      ip,
      result: spfResult.result,
      record: spfRecord,
      matchedMechanism: spfResult.matchedMechanism,
      dns: { aRecords, mxRecords },
      includeRecords,
    });

    // Single response serving BOTH audiences: `trace`/`dns` for engineers,
    // `commercial` for the business summary panel in the UI.
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
    // Any unexpected failure becomes a clean HTTP 500 so the UI can recover.
    logger.error(`/api/spf/evaluate error: ${err.message}`);
    return res.status(500).json({ error: 'SPF evaluation failed', details: err.message });
  }
}

// Two URLs, one handler — keeps older UI calls (/evaluate) working alongside /check.
router.post('/check', handleEvaluate);
router.post('/evaluate', handleEvaluate);

// ─────────────────────────────────────────────────────────────
// POST /api/spf/simulate — the "what-if" attack demo endpoint
// ─────────────────────────────────────────────────────────────
// Runs one sender against BOTH policy strengths (~all and -all) side by side,
// so the audience can see exactly how enforcement choice changes the outcome.
router.post('/simulate', async (req, res) => {
  try {
    const { domain, attackerIP, scenarioKey } = req.body;

    // Same fail-fast validation as the live audit endpoint.
    if (!domain || !attackerIP) {
      return res.status(400).json({ error: 'domain and attackerIP are required.' });
    }

    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: `"${domain}" does not look like a valid domain.` });
    }

    if (!isValidIP(attackerIP)) {
      return res.status(400).json({ error: `"${attackerIP}" does not look like a valid IPv4 address.` });
    }

    // Resolve which canned story to run: explicit key first, then domain match.
    let scenario = getSimulatorScenario(scenarioKey);
    if (!scenario) {
      scenario = findSimulatorScenarioByDomain(domain);
      if (scenario) {
        logger.info(`/api/spf/simulate fallback scenario by domain ${scenario.domain}`);
      }
    }

    // Defaults use LIVE DNS; if a scenario matched, we swap in its fake DNS below.
    let lookupRecordFn = lookupSPFRecord;
    let dnsResolver = null;
    let effectiveDomain = domain;
    let effectiveAttackerIP = attackerIP;

    if (scenario) {
      // Inject the scenario's sandboxed DNS so the demo is deterministic & safe.
      dnsResolver = buildSimulatedDnsResolver(scenario);
      lookupRecordFn = async (lookupDomain) => scenario.recordMap[lookupDomain] || null;
      effectiveDomain = scenario.domain || domain;
      effectiveAttackerIP = scenario.attackerIP || attackerIP;
      logger.info(`/api/spf/simulate scenario ${scenarioKey || scenario.domain} -> ${effectiveDomain} ${effectiveAttackerIP}`);
    }

    // Evaluate ONCE to get the baseline verdict; both policies reuse this result.
    const baseline = await evaluateSPFInteractive(effectiveDomain, effectiveAttackerIP, lookupRecordFn, dnsResolver);
    const aRecords = scenario ? scenario.aRecords[effectiveDomain] || [] : await lookupARecords(effectiveDomain);
    const mxRecords = scenario ? scenario.mxRecords[effectiveDomain] || [] : await lookupMXRecords(effectiveDomain);
    const spfRecord = baseline.record || (scenario ? scenario.recordMap[effectiveDomain] : await lookupSPFRecord(effectiveDomain));

    // The A/B comparison: same sender, soft (~all) vs hard (-all) enforcement.
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

// Expose the router so server/app.js can mount it under /api/spf.
module.exports = router;
