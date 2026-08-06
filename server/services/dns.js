/**
 * ============================================================
 * dns.js — DNS lookup helpers for SPF/DKIM/DMARC
 * ============================================================
 *
 * This service encapsulates DNS TXT lookups used by the analyser
 * route and SPF/DKIM/DMARC helpers.
 */

const dnsPromises = require('dns').promises;
const dnsCallback = require('dns');
const { promisify } = require('util');
const logger = require('../utils/logger');

// Try to set DNS servers, but fall back to system defaults if they fail
try {
  dnsCallback.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']);
  dnsPromises.setDefaultResultOrder('verbatim');
} catch (err) {
  logger.warn(`Could not set custom DNS servers, using system defaults: ${err.message}`);
}

const resolveA = dnsPromises.resolveA
  || dnsPromises.resolve4
  || (typeof dnsCallback.resolve4 === 'function' ? promisify(dnsCallback.resolve4) : null);

const TXT_RECORD_TYPES = {
  SPF: 'v=spf1',
  DKIM: 'v=DKIM1',
  DMARC: 'v=DMARC1',
};

const normalizeTxtRecords = (records) => {
  if (!Array.isArray(records)) return [];
  return records
    .map(record => Array.isArray(record) ? record.join('') : String(record))
    .map(text => text.trim())
    .filter(Boolean);
};

const findTxtRecord = (records, matcher) => {
  const normalized = normalizeTxtRecords(records);

  if (typeof matcher === 'string') {
    const prefix = matcher.toLowerCase();
    return normalized.find(record => record.toLowerCase().startsWith(prefix)) || null;
  }

  if (typeof matcher === 'function') {
    return normalized.find(record => matcher(record)) || null;
  }

  return null;
};

const isDkimTxtRecord = (record) => {
  const normalized = record.toLowerCase();
  return normalized.startsWith(TXT_RECORD_TYPES.DKIM.toLowerCase())
    || normalized.startsWith('k=rsa')
    || normalized.startsWith('k=ed25519')
    || normalized.startsWith('p=');
};

const { Resolver } = require('dns').promises;

const lookupTxtRecords = async (name) => {
  try {
    // Add timeout wrapper - 30 seconds with retry logic
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('DNS lookup timeout')), 30000)
    );

    const records = await Promise.race([
      dnsPromises.resolveTxt(name),
      timeoutPromise
    ]);
    return normalizeTxtRecords(records);
  } catch (err) {
    if (['ENOTFOUND', 'ENODATA', 'ENOTIMP', 'ESERVFAIL', 'ETIMEOUT', 'SERVFAIL', 'ECONNREFUSED', 'EAI_AGAIN'].includes(err.code) || err.message === 'DNS lookup timeout') {
      logger.info(`DNS TXT lookup for ${name} returned no data (${err.code || 'timeout'})`);
      return [];
    }
    logger.error(`DNS TXT lookup failed for ${name}: ${err.message}`);
    throw err;
  }
};

async function lookupSPFRecord(domain) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('lookupSPFRecord requires a valid domain string');
  }

  const records = await lookupTxtRecords(domain);
  const spfRecord = findTxtRecord(records, TXT_RECORD_TYPES.SPF);

  if (!spfRecord) {
    logger.info(`No SPF TXT record found for ${domain}`);
    return null;
  }

  logger.info(`Found SPF record for ${domain}: ${spfRecord}`);
  return spfRecord;
}

async function lookupDMARCRecord(domain) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('lookupDMARCRecord requires a valid domain string');
  }

  const name = `_dmarc.${domain}`;
  const records = await lookupTxtRecords(name);
  const dmarcRecord = findTxtRecord(records, TXT_RECORD_TYPES.DMARC);

  if (!dmarcRecord) {
    logger.info(`No DMARC TXT record found for ${domain}`);
    return null;
  }

  logger.info(`Found DMARC record for ${domain}: ${dmarcRecord}`);
  return dmarcRecord;
}

async function lookupDKIMRecord(domain, selector = 'default') {
  if (!domain || typeof domain !== 'string') {
    throw new Error('lookupDKIMRecord requires a valid domain string');
  }
  if (!selector || typeof selector !== 'string') {
    throw new Error('lookupDKIMRecord requires a valid selector string');
  }

  const normalizedSelector = selector.trim();
  const selectorPattern = /^[A-Za-z0-9_\-]+$/;
  if (!selectorPattern.test(normalizedSelector)) {
    throw new Error('lookupDKIMRecord requires a valid selector string');
  }

  const name = `${normalizedSelector}._domainkey.${domain}`;
  const records = await lookupTxtRecords(name);
  const dkimRecord = findTxtRecord(records, isDkimTxtRecord);

  if (!dkimRecord) {
    logger.info(`No DKIM TXT record found for ${selector}._domainkey.${domain}`);
    return null;
  }

  logger.info(`Found DKIM record for ${selector}._domainkey.${domain}: ${dkimRecord}`);
  return dkimRecord;
}

async function lookupARecords(domain) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('lookupARecords requires a valid domain string');
  }
  try {
    if (!resolveA) {
      throw new Error('DNS A lookup not supported');
    }
    return await resolveA(domain);
  } catch (err) {
    if (['ENOTFOUND', 'ENODATA', 'ENOTIMP', 'ESERVFAIL', 'ETIMEOUT', 'SERVFAIL'].includes(err.code)) {
      return [];
    }
    throw err;
  }
}

async function lookupMXRecords(domain) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('lookupMXRecords requires a valid domain string');
  }
  try {
    return await dnsPromises.resolveMx(domain);
  } catch (err) {
    if (['ENOTFOUND', 'ENODATA', 'ENOTIMP', 'ESERVFAIL', 'ETIMEOUT', 'SERVFAIL'].includes(err.code)) {
      return [];
    }
    throw err;
  }
}

async function checkDnsPropagation(domain, recordName = '', expectedValue = '', recordType = 'TXT') {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain is required');
  }

  const resolvers = [
    { name: 'Google', ip: '8.8.8.8' },
    { name: 'Cloudflare', ip: '1.1.1.1' },
    { name: 'OpenDNS', ip: '208.67.222.222' },
  ];

  const results = await Promise.all(resolvers.map(async (resolverInfo) => {
    const resolver = new Resolver();
    resolver.setServers([resolverInfo.ip]);

    try {
      const records = await Promise.race([
        resolver.resolveTxt(recordName ? `${recordName}.${domain}` : domain),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
      ]);

      const normalized = normalizeTxtRecords(records);
      const matched = expectedValue
        ? normalized.some((value) => String(value).includes(String(expectedValue)))
        : normalized.length > 0;

      return {
        resolver: resolverInfo.name,
        ip: resolverInfo.ip,
        status: matched ? 'updated' : 'old',
        records: normalized,
        error: null,
      };
    } catch (err) {
      return {
        resolver: resolverInfo.name,
        ip: resolverInfo.ip,
        status: err.message === 'timeout' ? 'timeout' : 'not_found',
        records: [],
        error: err.message,
      };
    }
  }));

  const updatedCount = results.filter((result) => result.status === 'updated').length;
  const status = updatedCount === results.length
    ? 'fully-propagated'
    : updatedCount > 0
      ? 'partially-propagated'
      : 'not-propagated';

  return {
    domain,
    checkedAt: new Date().toISOString(),
    recordType,
    expectedValue,
    results,
    summary: {
      total: results.length,
      updated: updatedCount,
      pending: results.length - updatedCount,
      status,
    },
  };
}

module.exports = {
  lookupSPFRecord,
  lookupDMARCRecord,
  lookupDKIMRecord,
  lookupARecords,
  lookupMXRecords,
  checkDnsPropagation,
};
