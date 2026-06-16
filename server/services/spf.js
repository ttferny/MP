/**
 * ============================================================
 * spf.js — SPF (Sender Policy Framework) Evaluator
 * Tiffany's deliverable.
 * ============================================================
 *
 * WHAT IS SPF? (simple version for pitching)
 * ------------------------------------------
 * Imagine a company publishes a list saying:
 *   "Only these mail servers are allowed to send email on our behalf."
 * That list is stored in DNS as a TXT record.
 *
 * When an email arrives, the receiving server checks:
 *   "Is the IP that sent this email on the approved list?"
 *   ✅ YES → SPF PASS   (email is from a legitimate server)
 *   ❌ NO  → SPF FAIL   (possible spoofing attempt)
 *
 * HOW THIS FILE LINKS TO THE REST OF THE PROJECT:
 * ------------------------------------------------
 *  parser.js  →  spf.js  →  dmarc.js
 *
 *  1. parser.js extracts: senderIP, envelopeDomain from the raw email header
 *  2. spf.js takes those values, looks up the domain's SPF DNS record,
 *     then checks if the senderIP is authorised
 *  3. The result { result, reason } is passed to dmarc.js for final verdict
 */

const { lookupSPFRecord } = require('./dns');
const logger = require('../utils/logger');

// ─────────────────────────────────────────────
// CONSTANTS — SPF result strings (RFC 7208)
// ─────────────────────────────────────────────
const SPF_RESULTS = {
  PASS:      'pass',       // IP is authorised — email is legitimate
  FAIL:      'fail',       // IP is NOT authorised — likely spoofed
  SOFTFAIL:  'softfail',   // IP is suspicious but not hard-blocked (~all)
  NEUTRAL:   'neutral',    // Domain makes no claim (?all)
  NONE:      'none',       // No SPF record found for this domain
  PERMERROR: 'permerror',  // Permanent error — bad SPF syntax
  TEMPERROR: 'temperror',  // Temporary error — DNS lookup failed
};

// ─────────────────────────────────────────────
// HELPER: Convert CIDR notation to an IP range checker
// e.g. "192.168.1.0/24" → checks if an IP falls in that subnet
// ─────────────────────────────────────────────
function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function isIPv6(address) {
  return String(address || '').includes(':');
}

function ipMatchesCIDR(ip, cidr) {
  const [base, prefix] = cidr.split('/');
  const bits = parseInt(prefix ?? '32', 10);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

// ─────────────────────────────────────────────
// HELPER: Parse SPF record string into mechanism list
//
// An SPF record looks like:
//   "v=spf1 ip4:1.2.3.4 include:sendgrid.net -all"
//
// We split it into tokens and categorise each one.
// ─────────────────────────────────────────────
function parseSPFRecord(record = '') {
  const tokens = record.trim().split(/\s+/);

  // First token must be "v=spf1"
  if (!tokens[0] || tokens[0].toLowerCase() !== 'v=spf1') {
    throw new Error('Invalid SPF record: must start with v=spf1');
  }

  const mechanisms = [];

  for (const token of tokens.slice(1)) {
    // Qualifier: + (pass), - (fail), ~ (softfail), ? (neutral)
    // Default qualifier is + (pass) when omitted
    let qualifier = '+';
    let mech = token;

    if (['+', '-', '~', '?'].includes(token[0])) {
      qualifier = token[0];
      mech = token.slice(1);
    }

    const colonIdx = mech.indexOf(':');
    const slashIdx = mech.indexOf('/');
    const mechName = colonIdx !== -1
      ? mech.slice(0, colonIdx).toLowerCase()
      : slashIdx !== -1
      ? mech.slice(0, slashIdx).toLowerCase()
      : mech.toLowerCase();

    const mechValue = colonIdx !== -1 ? mech.slice(colonIdx + 1) : '';

    mechanisms.push({ qualifier, mechName, mechValue, raw: token });
  }

  return mechanisms;
}

// ─────────────────────────────────────────────
// HELPER: Qualifier → SPF result string
// ─────────────────────────────────────────────
function qualifierToResult(q) {
  return { '+': SPF_RESULTS.PASS, '-': SPF_RESULTS.FAIL,
           '~': SPF_RESULTS.SOFTFAIL, '?': SPF_RESULTS.NEUTRAL }[q] || SPF_RESULTS.NEUTRAL;
}

// ─────────────────────────────────────────────
// CORE: Evaluate a single SPF mechanism against senderIP
//
// SPF supports several mechanism types:
//   ip4 / ip6  — direct IP or CIDR range check
//   a          — check if senderIP matches the domain's A record
//   mx         — check if senderIP matches the domain's MX servers
//   include    — recursively check another domain's SPF record
//   all        — catch-all (always matches, applied last)
// ─────────────────────────────────────────────
async function evaluateMechanism(mech, senderIP, domain, dns, depth = 0, stats = null, lookupRecordFn = lookupSPFRecord) {
  // Guard against infinite loops from circular includes
  if (depth > 10) {
    logger.warn('SPF: max include depth reached');
    return { matched: false };
  }

  const { mechName, mechValue, qualifier } = mech;

  switch (mechName) {

    // ip4:1.2.3.4 or ip4:1.2.3.0/24
    case 'ip4': {
      const matched = mechValue.includes('/')
        ? ipMatchesCIDR(senderIP, mechValue)
        : senderIP === mechValue;
      if (matched) logger.info(`SPF: ip4 match — ${mechValue}`);
      return {
        matched,
        result: qualifierToResult(qualifier),
        detail: matched ? `Sender IP in ${mechValue}` : `Sender IP not in ${mechValue}`,
      };
    }

    // ip6 — simplified: exact string match (full IPv6 support is out of scope for POC)
    case 'ip6': {
      const matched = senderIP === mechValue;
      return {
        matched,
        result: qualifierToResult(qualifier),
        detail: matched ? `Sender IP matches ${mechValue}` : 'Sender IP does not match IPv6 value',
      };
    }

    // all — always matches; used as the last catch-all mechanism
    case 'all': {
      logger.info(`SPF: 'all' mechanism matched with qualifier '${qualifier}'`);
      return {
        matched: true,
        result: qualifierToResult(qualifier),
        detail: 'Matches any sender',
      };
    }

    // a — check if senderIP matches the A record of the domain (or mechValue if specified)
    case 'a': {
      const targetDomain = mechValue || domain;
      try {
        if (stats) stats.lookupCount += 1;
        // Resolve both A and AAAA so IPv6 senders can be matched
        const aRecords = await dns.resolveA(targetDomain).catch(() => []);
        const aaaaRecords = (dns.resolveAAAA ? await dns.resolveAAAA(targetDomain).catch(() => []) : []);
        const allAddrs = [...(aRecords || []), ...(aaaaRecords || [])];
        const matched = allAddrs.some((ip) => {
          // If mechanism uses CIDR (e.g. /24), only attempt IPv4 CIDR matching
          if (mechValue.includes('/') && !isIPv6(mechValue)) {
            return ipMatchesCIDR(senderIP, `${ip}${mechValue.slice(mechValue.indexOf('/'))}`);
          }
          // For IPv6 or simple exact match, compare string equality
          return senderIP === ip;
        });
        if (matched) logger.info(`SPF: 'a' record match for ${targetDomain}`);
        return {
          matched,
          result: qualifierToResult(qualifier),
          detail: matched ? `Sender IP matches A record for ${targetDomain}` : `Sender IP not in A records for ${targetDomain}`,
        };
      } catch {
        return { matched: false, detail: `A lookup failed for ${targetDomain}` };
      }
    }

    // mx — check if senderIP matches any of the domain's MX mail servers
    case 'mx': {
      const targetDomain = mechValue || domain;
      try {
        if (stats) stats.lookupCount += 1;
        const mxRecords = await dns.resolveMx(targetDomain);
        for (const mx of mxRecords) {
          if (stats) stats.lookupCount += 1;
          const aRecords = await dns.resolveA(mx.exchange).catch(() => []);
          const aaaaRecords = (dns.resolveAAAA ? await dns.resolveAAAA(mx.exchange).catch(() => []) : []);
          const allAddrs = [...(aRecords || []), ...(aaaaRecords || [])];
          if (allAddrs.includes(senderIP)) {
            logger.info(`SPF: 'mx' match — ${mx.exchange}`);
            return {
              matched: true,
              result: qualifierToResult(qualifier),
              detail: `Sender IP matches MX host ${mx.exchange}`,
            };
          }
        }
        return { matched: false, detail: `Sender IP not in MX records for ${targetDomain}` };
      } catch {
        return { matched: false, detail: `MX lookup failed for ${targetDomain}` };
      }
    }

    // include — recursively evaluate another domain's SPF record
    // e.g. include:_spf.google.com means "also trust Google's approved servers"
    case 'include': {
      if (!mechValue) return { matched: false, detail: 'Include missing domain' };
      logger.info(`SPF: following include → ${mechValue}`);
      const includeResult = await evaluateSPFRecord(mechValue, senderIP, dns, depth + 1, stats, lookupRecordFn);
      const matched = includeResult.result === SPF_RESULTS.PASS;
      return {
        matched,
        result: qualifierToResult(qualifier),
        detail: matched
          ? `Include ${mechValue} returned pass`
          : `Include ${mechValue} returned ${includeResult.result}`,
      };
    }

    // redirect — treat another domain's SPF as this domain's policy
    case 'redirect': {
      if (!mechValue) return { matched: false, detail: 'Redirect missing domain' };
      logger.info(`SPF: redirect → ${mechValue}`);
      const redirectResult = await evaluateSPFRecord(mechValue, senderIP, dns, depth + 1, stats, lookupRecordFn);
      return {
        matched: true,
        result: redirectResult.result,
        redirectResult,
      };
    }

    default:
      logger.warn(`SPF: unknown mechanism '${mechName}' — skipping`);
      return { matched: false, detail: `Unsupported mechanism '${mechName}'` };
  }
}

// ─────────────────────────────────────────────
// CORE: Evaluate the full SPF record for a domain
// Walks through each mechanism in order, returns on first match.
// ─────────────────────────────────────────────
async function evaluateSPFRecord(domain, senderIP, dns, depth = 0, stats = null, lookupRecordFn = lookupSPFRecord) {
  const localStats = stats || { lookupCount: 0, trace: [] };
  let spfRecord;

  try {
    localStats.lookupCount += 1;
    spfRecord = await lookupRecordFn(domain);
  } catch (err) {
    logger.warn(`SPF: DNS lookup failed for ${domain} — ${err.message}`);
    if (localStats.trace) {
      localStats.trace.push({
        domain,
        mechanism: 'dns',
        detail: `DNS lookup failed: ${err.message}`,
        outcome: SPF_RESULTS.TEMPERROR,
      });
    }
    return { result: SPF_RESULTS.TEMPERROR, reason: `DNS lookup failed: ${err.message}`, record: null, trace: localStats.trace, lookupCount: localStats.lookupCount };
  }

  if (!spfRecord) {
    logger.info(`SPF: No SPF record found for ${domain}`);
    if (localStats.trace) {
      localStats.trace.push({
        domain,
        mechanism: 'record',
        detail: 'No SPF record found',
        outcome: SPF_RESULTS.NONE,
      });
    }
    return { result: SPF_RESULTS.NONE, reason: `No SPF record found for ${domain}`, record: null, trace: localStats.trace, lookupCount: localStats.lookupCount };
  }

  let mechanisms;
  try {
    mechanisms = parseSPFRecord(spfRecord);
  } catch (err) {
    logger.error(`SPF: Failed to parse record — ${err.message}`);
    if (localStats.trace) {
      localStats.trace.push({
        domain,
        mechanism: 'record',
        detail: err.message,
        outcome: SPF_RESULTS.PERMERROR,
      });
    }
    return { result: SPF_RESULTS.PERMERROR, reason: err.message, record: spfRecord, trace: localStats.trace, lookupCount: localStats.lookupCount };
  }

  // Walk mechanisms in order — first match wins
  for (const mech of mechanisms) {
    const { matched, result, redirectResult, detail } = await evaluateMechanism(mech, senderIP, domain, dns, depth, localStats, lookupRecordFn);
    if (localStats.trace) {
      localStats.trace.push({
        domain,
        mechanism: mech.raw,
        detail: detail || 'Evaluated',
        outcome: matched ? result : 'no-match',
      });
    }
    if (matched) {
      if (mech.mechName === 'redirect' && redirectResult) {
        logger.info(`SPF result: ${redirectResult.result} (redirect '${mech.raw}')`);
        return {
          result: redirectResult.result,
          reason: redirectResult.reason || `Redirected to ${mech.mechValue}`,
          record: redirectResult.record || spfRecord,
          matchedMechanism: mech.raw,
          trace: localStats.trace,
          lookupCount: localStats.lookupCount,
        };
      }

      logger.info(`SPF result: ${result} (matched '${mech.raw}')`);
      return {
        result,
        reason: `Matched mechanism: ${mech.raw}`,
        record: spfRecord,
        matchedMechanism: mech.raw,
        trace: localStats.trace,
        lookupCount: localStats.lookupCount,
      };
    }
  }

  // No mechanism matched → implicit neutral
  return {
    result: SPF_RESULTS.NEUTRAL,
    reason: 'No mechanism matched — implicit neutral',
    record: spfRecord,
    matchedMechanism: null,
    trace: localStats.trace,
    lookupCount: localStats.lookupCount,
  };
}

// ─────────────────────────────────────────────
// MAIN EXPORT: checkSPF
//
// Called by routes/analyse.js after parser.js runs.
//
// Input: parsed object from parser.js
//   { envelopeDomain, senderIP }
//
// Output:
//   { result, reason, record, matchedMechanism, domain, ip }
// ─────────────────────────────────────────────
async function checkSPF(parsed) {
  const { envelopeDomain, senderIP } = parsed;

  logger.info(`SPF check — domain: ${envelopeDomain}, IP: ${senderIP}`);

  // Validation: we need both a domain and an IP to run SPF
  if (!envelopeDomain) {
    return { result: SPF_RESULTS.NONE, reason: 'No envelope domain found in headers', domain: '', ip: senderIP };
  }
  if (!senderIP) {
    return { result: SPF_RESULTS.NONE, reason: 'No sender IP found in Received headers', domain: envelopeDomain, ip: '' };
  }

  // Use Node's built-in dns/promises module
  const dnsPromises = require('dns').promises;
  const resolver = buildDnsResolver(dnsPromises);

  const spfResult = await evaluateSPFRecord(envelopeDomain, senderIP, resolver);

  return {
    ...spfResult,
    domain: envelopeDomain,
    ip: senderIP,
  };
}

async function evaluateSPFInteractive(domain, senderIP, lookupRecordFn = lookupSPFRecord, dnsResolver = null) {
  const dnsPromises = require('dns').promises;
  const resolver = dnsResolver || buildDnsResolver(dnsPromises);
  const stats = { lookupCount: 0, trace: [] };
  const spfResult = await evaluateSPFRecord(domain, senderIP, resolver, 0, stats, lookupRecordFn);
  return {
    ...spfResult,
    domain,
    ip: senderIP,
    trace: spfResult.trace || stats.trace,
    lookupCount: spfResult.lookupCount ?? stats.lookupCount,
  };
}

function buildDnsResolver(dnsPromises) {
  const dns = require('dns');
  const { promisify } = require('util');
  const resolve4Fallback = typeof dns.resolve4 === 'function'
    ? promisify(dns.resolve4)
    : null;
  const resolveMxFallback = typeof dns.resolveMx === 'function'
    ? promisify(dns.resolveMx)
    : null;

  return {
    resolveA: dnsPromises.resolveA
      || dnsPromises.resolve4
      || resolve4Fallback
      || (async () => { throw new Error('DNS A lookup not supported'); }),
    resolveMx: dnsPromises.resolveMx
      || resolveMxFallback
      || (async () => { throw new Error('DNS MX lookup not supported'); }),
    resolveAAAA: dnsPromises.resolve6
      || (typeof dns.resolve6 === 'function' ? promisify(dns.resolve6) : null)
      || (async () => { throw new Error('DNS AAAA lookup not supported'); }),
  };
}

module.exports = { checkSPF, parseSPFRecord, evaluateSPFRecord, evaluateSPFInteractive, SPF_RESULTS };