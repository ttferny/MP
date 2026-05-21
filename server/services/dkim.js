/**
 * ============================================================
 * dkim.js — DKIM verification helper
 * ============================================================
 *
 * This service validates the presence of a DKIM signature and
 * retrieves the public key from DNS. For this prototype, it
 * performs structural verification and DNS key lookup, not a
 * full cryptographic signature validation.
 */

const { lookupDKIMRecord } = require('./dns');
const logger = require('../utils/logger');
const { isValidDomain } = require('../utils/validate');

const isNonEmptyString = (value) => typeof value === 'string' && value.trim().length > 0;

const buildResult = ({ status, reason, domain = '', selector = '', algorithm = '', dnsRecord = null }) => ({
  status,
  result: status,
  reason,
  domain,
  selector,
  algorithm,
  dnsRecord,
});

const verifyDKIM = async (parsed) => {
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('verifyDKIM requires a parsed header object');
  }

  const dkimSignature = parsed.dkimSignature || {};

  if (Object.keys(dkimSignature).length === 0) {
    logger.warn('DKIM: no signature found in headers');
    return buildResult({
      status: 'none',
      reason: 'No DKIM signature header present',
    });
  }

  const domain = dkimSignature.d || '';
  const selector = dkimSignature.s || '';
  const algorithm = dkimSignature.a || '';

  // Validate domain (d=) and selector (s=)
  if (!isNonEmptyString(domain) || !isNonEmptyString(selector)) {
    logger.warn('DKIM: signature missing domain or selector');
    return buildResult({
      status: 'fail',
      reason: 'DKIM signature is incomplete (missing d= or s=)',
      domain,
      selector,
      algorithm,
    });
  }

  if (!isValidDomain(domain)) {
    logger.warn(`DKIM: invalid domain in signature: ${domain}`);
    return buildResult({
      status: 'fail',
      reason: `DKIM signature contains invalid domain: ${domain}`,
      domain,
      selector,
      algorithm,
    });
  }

  // Selector should be a short token (letters, digits, hyphen, underscore)
  const selectorPattern = /^[A-Za-z0-9_\-]+$/;
  if (!selectorPattern.test(selector)) {
    logger.warn(`DKIM: invalid selector in signature: ${selector}`);
    return buildResult({
      status: 'fail',
      reason: `DKIM signature contains invalid selector: ${selector}`,
      domain,
      selector,
      algorithm,
    });
  }

  if (dkimSignature.v && dkimSignature.v !== '1') {
    logger.warn(`DKIM: unsupported version ${dkimSignature.v}`);
    return buildResult({
      status: 'fail',
      reason: `Unsupported DKIM version: ${dkimSignature.v}`,
      domain,
      selector,
      algorithm,
    });
  }

  if (!isNonEmptyString(dkimSignature.b) || !isNonEmptyString(dkimSignature.bh)) {
    logger.warn('DKIM: signature missing b= or bh= tag');
    return buildResult({
      status: 'fail',
      reason: 'DKIM signature is missing required b= or bh= tag',
      domain,
      selector,
      algorithm,
    });
  }

  let dnsRecord = null;
  try {
    dnsRecord = await lookupDKIMRecord(domain, selector);
  } catch (err) {
    logger.error(`DKIM DNS lookup failed: ${err.message}`);
    return buildResult({
      status: 'temperror',
      reason: `DKIM DNS lookup failed: ${err.message}`,
      domain,
      selector,
      algorithm,
    });
  }

  if (!dnsRecord) {
    logger.warn(`DKIM: key record not found for ${selector}._domainkey.${domain}`);
    return buildResult({
      status: 'fail',
      reason: `DKIM public key not found for selector ${selector}`,
      domain,
      selector,
      algorithm,
    });
  }

  logger.info(`DKIM: public key found for ${selector}._domainkey.${domain}`);
  return buildResult({
    status: 'pass',
    reason: 'DKIM signature and DNS public key found',
    domain,
    selector,
    algorithm,
    dnsRecord,
  });
};

module.exports = { verifyDKIM };
