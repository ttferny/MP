/**
 * ============================================================
 * autoDnsChecker.js — Automated DNS & DKIM Checker
 * ============================================================
 * 
 * Automatically checks DNS records (SPF, DKIM, DMARC) for a domain
 * and performs DKIM validation on email headers.
 */

const { 
  lookupSPFRecord, 
  lookupDMARCRecord, 
  lookupDKIMRecord,
  lookupTxtRecords
} = require('./dns');
const { verifyDKIM } = require('./dkim');
const { parseEmailHeader } = require('./parser');
const { isValidDomain, isValidEmail } = require('../utils/validate');
const logger = require('../utils/logger');

/**
 * Auto-check DNS records for a domain
 * Returns: SPF, DMARC, and common DKIM selectors
 */
async function autoDnsCheck(domain) {
  if (!domain || !isValidDomain(domain)) {
    throw new Error('Invalid domain provided');
  }

  logger.info(`Auto-checking DNS for domain: ${domain}`);

  const results = {
    domain,
    timestamp: new Date().toISOString(),
    records: {
      spf: null,
      dmarc: null,
      dkim: [],
    },
    summary: {
      hasSPF: false,
      hasDMARC: false,
      dkimSelectors: [],
    },
  };

  try {
    // Check SPF
    try {
      const spfRecord = await lookupSPFRecord(domain);
      results.records.spf = spfRecord ? {
        status: 'found',
        record: spfRecord,
      } : {
        status: 'not_found',
        record: null,
      };
      results.summary.hasSPF = !!spfRecord;
    } catch (err) {
      logger.warn(`SPF lookup failed for ${domain}: ${err.message}`);
      results.records.spf = { status: 'error', error: err.message };
    }

    // Check DMARC
    try {
      const dmarcRecord = await lookupDMARCRecord(domain);
      results.records.dmarc = dmarcRecord ? {
        status: 'found',
        record: dmarcRecord,
      } : {
        status: 'not_found',
        record: null,
      };
      results.summary.hasDMARC = !!dmarcRecord;
    } catch (err) {
      logger.warn(`DMARC lookup failed for ${domain}: ${err.message}`);
      results.records.dmarc = { status: 'error', error: err.message };
    }

    // Check common DKIM selectors
    const commonSelectors = [
      'default',
      'mail',
      'selector1',
      'selector2',
      'google',
      'k1',
      'amazon',
      'sendgrid',
    ];

    for (const selector of commonSelectors) {
      try {
        const dkimRecord = await lookupDKIMRecord(domain, selector);
        if (dkimRecord) {
          results.records.dkim.push({
            selector,
            status: 'found',
            record: dkimRecord,
          });
          results.summary.dkimSelectors.push(selector);
        }
      } catch (err) {
        // Skip this selector if not found
        logger.debug(`DKIM selector '${selector}' not found for ${domain}`);
      }
    }

    if (results.records.dkim.length === 0) {
      results.records.dkim = [{
        status: 'none_found',
        message: 'No DKIM records found for common selectors',
      }];
    }

  } catch (err) {
    logger.error(`Auto DNS check failed for ${domain}: ${err.message}`);
    throw err;
  }

  return results;
}

/**
 * Auto-validate DKIM from raw header
 * Extracts DKIM signature and performs lookup
 */
async function autoDkimValidation(rawHeader) {
  if (!rawHeader || typeof rawHeader !== 'string') {
    throw new Error('Invalid header provided');
  }

  logger.info('Auto-validating DKIM from header');

  try {
    // Parse the header
    const parsed = parseEmailHeader(rawHeader);

    // Verify DKIM
    const dkimResult = await verifyDKIM(parsed);

    // If DKIM signature exists, try to lookup the public key
    let dnsLookup = null;
    if (dkimResult.domain && dkimResult.selector) {
      try {
        dnsLookup = await lookupDKIMRecord(dkimResult.domain, dkimResult.selector);
      } catch (err) {
        logger.debug(`Failed to lookup DKIM record: ${err.message}`);
      }
    }

    return {
      header: {
        from: parsed.from,
        fromDomain: parsed.fromDomain,
        returnPath: parsed.returnPath,
        date: parsed.date,
      },
      dkim: {
        ...dkimResult,
        publicKeyFound: !!dnsLookup,
        publicKey: dnsLookup,
      },
    };
  } catch (err) {
    logger.error(`Auto DKIM validation failed: ${err.message}`);
    throw err;
  }
}

/**
 * Comprehensive auto-check: domain + optional header
 */
async function autoFullCheck(domain, rawHeader = null) {
  if (!domain || !isValidDomain(domain)) {
    throw new Error('Invalid domain provided');
  }

  logger.info(`Full auto-check for domain: ${domain}`);

  const dnsResults = await autoDnsCheck(domain);
  let headerResults = null;

  if (rawHeader) {
    try {
      headerResults = await autoDkimValidation(rawHeader);
    } catch (err) {
      logger.warn(`Header validation failed: ${err.message}`);
      headerResults = { error: err.message };
    }
  }

  return {
    domain,
    dnsCheck: dnsResults,
    headerCheck: headerResults,
  };
}

module.exports = {
  autoDnsCheck,
  autoDkimValidation,
  autoFullCheck,
};
