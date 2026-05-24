/**
 * ============================================================
 * dns.js — DNS lookup helpers for SPF/DKIM/DMARC
 * ============================================================
 *
 * This service encapsulates DNS TXT lookups used by the analyser
 * route and SPF/DKIM/DMARC helpers.
 */

const dns = require('dns').promises;
const logger = require('../utils/logger');

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

const lookupTxtRecords = async (name) => {
  try {
    const records = await dns.resolveTxt(name);
    return normalizeTxtRecords(records);
  } catch (err) {
    if (['ENOTFOUND', 'ENODATA', 'ENOTIMP', 'ESERVFAIL', 'ETIMEOUT', 'SERVFAIL', 'ECONNREFUSED', 'EAI_AGAIN'].includes(err.code)) {
      logger.info(`DNS TXT lookup for ${name} returned no data (${err.code})`);
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
    return await dns.resolveA(domain);
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
    return await dns.resolveMx(domain);
  } catch (err) {
    if (['ENOTFOUND', 'ENODATA', 'ENOTIMP', 'ESERVFAIL', 'ETIMEOUT', 'SERVFAIL'].includes(err.code)) {
      return [];
    }
    throw err;
  }
}

module.exports = {
  lookupSPFRecord,
  lookupDMARCRecord,
  lookupDKIMRecord,
  lookupARecords,
  lookupMXRecords,
};
