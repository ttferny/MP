/**
 * ============================================================
 * validate.js — API Response Validator
 * Tiffany's deliverable — Phase 4.
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * After parser.js and spf.js produce their results, we need to
 * make sure the data going back to the frontend is:
 *   ✅ Complete   — no missing required fields
 *   ✅ Correct    — values are the right type and format
 *   ✅ Safe       — no unexpected/garbage data reaches the UI
 *
 * Think of it as a quality check at the end of the pipeline,
 * before the result JSON is sent to the browser.
 *
 * HOW IT LINKS TO THE REST OF THE PROJECT:
 * -----------------------------------------
 *   routes/analyse.js calls validateParsedHeader() after parser.js
 *   routes/analyse.js calls validateSPFResult()   after spf.js
 *   If validation fails, a 422 error is returned instead of bad data
 *
 *   parser.js → validateParsedHeader() → spf.js → validateSPFResult()
 *                                                        ↓
 *                                               dkim.js (Ashton)
 */

const logger = require('./logger');

// ─────────────────────────────────────────────
// HELPER: isNonEmptyString
// Returns true only if value is a string with at least 1 character.
// ─────────────────────────────────────────────
function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

// ─────────────────────────────────────────────
// HELPER: isValidIP
// Basic IPv4 validation — 4 octets, each 0-255.
// Used to check that senderIP from parser.js looks real.
// ─────────────────────────────────────────────
function isValidIP(ip) {
  if (!ip) return false;
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = parseInt(p, 10);
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

// ─────────────────────────────────────────────
// HELPER: isValidDomain
// Checks the domain looks like a real domain (e.g. "company.com").
// Rejects empty strings, IPs, and obviously malformed values.
// ─────────────────────────────────────────────
function isValidDomain(domain) {
  if (!domain) return false;
  // Must contain at least one dot and only valid hostname characters
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/.test(domain);
}

// ─────────────────────────────────────────────
// HELPER: isValidEmail
// Checks value looks like a valid email address.
// ─────────────────────────────────────────────
function isValidEmail(email) {
  if (!email) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ─────────────────────────────────────────────
// validateParsedHeader
//
// Validates the object returned by parser.js.
// Called in routes/analyse.js before passing parsed to spf.js.
//
// Returns: { valid: true } or { valid: false, errors: [...] }
// ─────────────────────────────────────────────
function validateParsedHeader(parsed) {
  const errors = [];

  if (!parsed || typeof parsed !== 'object') {
    return { valid: false, errors: ['parsed result is not an object'] };
  }

  // fromDomain — required, must look like a real domain
  if (!isNonEmptyString(parsed.fromDomain)) {
    errors.push('fromDomain is missing or empty');
  } else if (!isValidDomain(parsed.fromDomain)) {
    errors.push(`fromDomain "${parsed.fromDomain}" does not look like a valid domain`);
  }

  // fromEmail — required, must look like a real email
  if (!isNonEmptyString(parsed.fromEmail)) {
    errors.push('fromEmail is missing or empty');
  } else if (!isValidEmail(parsed.fromEmail)) {
    errors.push(`fromEmail "${parsed.fromEmail}" does not look like a valid email address`);
  }

  // envelopeDomain — required for SPF
  if (!isNonEmptyString(parsed.envelopeDomain)) {
    errors.push('envelopeDomain is missing — SPF check cannot proceed without it');
  }

  // senderIP — warn if missing (not a hard error — some headers omit it)
  if (!parsed.senderIP) {
    logger.warn('Validation: senderIP not found — SPF result may be limited');
  } else if (!isValidIP(parsed.senderIP)) {
    errors.push(`senderIP "${parsed.senderIP}" is not a valid IPv4 address`);
  }

  // dkimSignature — must be an object (can be empty if no DKIM)
  if (typeof parsed.dkimSignature !== 'object' || parsed.dkimSignature === null) {
    errors.push('dkimSignature must be an object (can be empty {}  if no DKIM header present)');
  }

  if (errors.length > 0) {
    logger.warn(`validateParsedHeader failed: ${errors.join(' | ')}`);
    return { valid: false, errors };
  }

  logger.info('validateParsedHeader: passed');
  return { valid: true, errors: [] };
}

// ─────────────────────────────────────────────
// validateSPFResult
//
// Validates the object returned by spf.js.
// Called in routes/analyse.js before passing spfResult to dkim.js.
//
// Returns: { valid: true } or { valid: false, errors: [...] }
// ─────────────────────────────────────────────
function validateSPFResult(spfResult) {
  const errors = [];

  const VALID_SPF_RESULTS = ['pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror'];

  if (!spfResult || typeof spfResult !== 'object') {
    return { valid: false, errors: ['spfResult is not an object'] };
  }

  // result — must be one of the defined RFC 7208 result strings
  if (!isNonEmptyString(spfResult.result)) {
    errors.push('spfResult.result is missing');
  } else if (!VALID_SPF_RESULTS.includes(spfResult.result.toLowerCase())) {
    errors.push(`spfResult.result "${spfResult.result}" is not a valid SPF result. Must be one of: ${VALID_SPF_RESULTS.join(', ')}`);
  }

  // reason — required for UI display
  if (!isNonEmptyString(spfResult.reason)) {
    errors.push('spfResult.reason is missing — UI needs this to explain the result');
  }

  // domain — required
  if (!isNonEmptyString(spfResult.domain)) {
    errors.push('spfResult.domain is missing');
  }

  // ip — warn if missing
  if (!spfResult.ip) {
    logger.warn('Validation: spfResult.ip is empty');
  }

  if (errors.length > 0) {
    logger.warn(`validateSPFResult failed: ${errors.join(' | ')}`);
    return { valid: false, errors };
  }

  logger.info(`validateSPFResult: passed (result=${spfResult.result})`);
  return { valid: true, errors: [] };
}

// ─────────────────────────────────────────────
// validateAnalyseResponse
//
// Final validation of the complete response object before it is
// sent back to the frontend by routes/analyse.js.
//
// Checks that all three protocol results are present and structured.
// ─────────────────────────────────────────────
function validateAnalyseResponse(responseObj) {
  const errors = [];

  if (!responseObj.parsed)          errors.push('response missing parsed header data');
  if (!responseObj.results)         errors.push('response missing results object');
  if (!responseObj.results?.spf)    errors.push('response missing spf result');
  if (!responseObj.results?.dkim)   errors.push('response missing dkim result');
  if (!responseObj.results?.dmarc)  errors.push('response missing dmarc result');

  if (errors.length > 0) {
    logger.warn(`validateAnalyseResponse failed: ${errors.join(' | ')}`);
    return { valid: false, errors };
  }

  logger.info('validateAnalyseResponse: full response is valid');
  return { valid: true, errors: [] };
}

module.exports = {
  validateParsedHeader,
  validateSPFResult,
  validateAnalyseResponse,
  isValidIP,
  isValidDomain,
  isValidEmail,
};