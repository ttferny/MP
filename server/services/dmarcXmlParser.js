/**
 * DMARC XML Parser Service
 * Parses DMARC aggregate XML reports into structured JSON
 * Handles various DMARC report formats from different mail providers
 */

const xml2js = require('xml2js');

/**
 * Parse DMARC XML report
 * @param {string} xmlContent - Raw XML content
 * @returns {Promise<Object>} Parsed DMARC report with metadata and records
 */
async function parseDMARCReport(xmlContent) {
  try {
    const parser = new xml2js.Parser();
    const parsed = await parser.parseStringPromise(xmlContent);

    // Extract feedback (top-level report container)
    const feedback = parsed.feedback;
    if (!feedback) {
      throw new Error('Invalid DMARC XML: missing feedback element');
    }

    // Extract metadata
    const reportMetadata = feedback['report_metadata']?.[0] || {};
    const metadata = {
      orgName: reportMetadata.org_name?.[0] || 'Unknown',
      email: reportMetadata.email?.[0] || 'unknown@example.com',
      reportId: reportMetadata.report_id?.[0] || 'unknown',
      dateRange: {
        begin: parseInt(reportMetadata.date_range?.[0]?.begin?.[0]) || 0,
        end: parseInt(reportMetadata.date_range?.[0]?.end?.[0]) || 0
      }
    };

    // Extract policy published
    const policyPublished = feedback['policy_published']?.[0] || {};
    const policy = {
      domain: policyPublished.domain?.[0] || 'unknown',
      adkim: policyPublished.adkim?.[0] || 'r',
      aspf: policyPublished.aspf?.[0] || 'r',
      p: policyPublished.p?.[0] || 'none',
      sp: policyPublished.sp?.[0] || null,
      pct: parseInt(policyPublished.pct?.[0]) || 100,
      rua: policyPublished.rua?.[0] || 'unknown',
      ruf: policyPublished.ruf?.[0] || null
    };

    // Extract records
    const recordElements = feedback.record || [];
    const records = recordElements.map(record => parseRecord(record, policy));

    return {
      metadata,
      policy,
      records,
      totalRecords: records.length,
      dateRange: {
        start: new Date(metadata.dateRange.begin * 1000).toISOString(),
        end: new Date(metadata.dateRange.end * 1000).toISOString()
      }
    };
  } catch (error) {
    throw new Error(`Failed to parse DMARC XML: ${error.message}`);
  }
}

/**
 * Parse individual record from DMARC report
 * @param {Object} record - XML record element
 * @param {Object} policy - DMARC policy from report
 * @returns {Object} Parsed record
 */
function parseRecord(record, policy) {
  const row = record.row?.[0] || {};
  const identifiers = record.identifiers?.[0] || {};
  const authResults = record.auth_results?.[0] || {};

  // Parse row data
  const rowData = {
    sourceIp: row.source_ip?.[0] || 'unknown',
    count: parseInt(row.count?.[0]) || 0,
    policyEvaluated: parsePolicy(row.policy_evaluated?.[0] || {})
  };

  // Parse identifiers
  const identifierData = {
    headerFrom: identifiers.header_from?.[0] || 'unknown',
    envelopeFrom: identifiers.envelope_from?.[0] || 'unknown',
    envelopeTo: identifiers.envelope_to?.[0] || 'unknown'
  };

  // Parse auth results
  const authData = {
    spf: parseAuthResult(authResults.spf?.[0] || {}),
    dkim: parseAuthResult(authResults.dkim?.map(d => d) || []),
    dmarc: parseAuthResult(authResults.dmarc?.[0] || {})
  };

  return {
    sourceIp: rowData.sourceIp,
    count: rowData.count,
    disposition: rowData.policyEvaluated.disposition || 'none',
    policyEvaluated: rowData.policyEvaluated,
    headerFrom: identifierData.headerFrom,
    envelopeFrom: identifierData.envelopeFrom,
    envelopeTo: identifierData.envelopeTo,
    spf: authData.spf,
    dkim: Array.isArray(authData.dkim) ? authData.dkim : [authData.dkim],
    dmarc: authData.dmarc
  };
}

/**
 * Parse policy_evaluated section
 * @param {Object} policyEvaluated - XML policy_evaluated element
 * @returns {Object} Parsed policy evaluation
 */
function parsePolicy(policyEvaluated) {
  return {
    disposition: policyEvaluated.disposition?.[0] || 'none',
    dkimAlign: policyEvaluated.dkim_align?.[0] || 'fail',
    spfAlign: policyEvaluated.spf_align?.[0] || 'fail',
    forwardedPolicy: policyEvaluated.forwarded_policy?.[0] || 'not-applicable'
  };
}

/**
 * Parse SPF/DKIM auth result
 * @param {Object} authResult - XML auth result element
 * @returns {Object} Parsed auth result
 */
function parseAuthResult(authResult) {
  if (Array.isArray(authResult)) {
    // Handle DKIM array
    return authResult.map(result => ({
      domain: result.domain?.[0] || 'unknown',
      result: result.result?.[0] || 'none',
      selector: result.selector?.[0] || 'unknown'
    }));
  }

  // Handle SPF or DMARC
  return {
    domain: authResult.domain?.[0] || 'unknown',
    result: authResult.result?.[0] || 'none',
    selector: authResult.selector?.[0] || null
  };
}

module.exports = {
  parseDMARCReport
};
