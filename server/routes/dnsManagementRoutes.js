/**
 * ============================================================
 * dnsManagementRoutes.js — DNS Record Management API Routes
 * ============================================================
 *
 * Complete CRUD API for managing DNS records
 */

const express = require('express');
const router = express.Router();
const dnsLib = require('../services/dnsLibrary');
const logger = require('../utils/logger');

/**
 * POST /api/dns-mgmt/records
 * Add a new DNS record
 */
router.post('/records', async (req, res) => {
  try {
    const { domain, type, name, content, target, ttl, priority, weight, port, flag, tag } = req.body;

    if (!domain || !type) {
      return res.status(400).json({ 
        error: 'domain and type are required',
        example: { domain: 'example.com', type: 'A', name: 'www', content: '192.168.1.1', ttl: 3600 }
      });
    }

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    const record = dnsLib.addRecord(domain, type, {
      name,
      content: content || target,
      ttl,
      priority,
      weight,
      port,
      flag,
      tag,
    });

    logger.info(`API: Added ${type} record for ${domain}`);
    return res.status(201).json({ success: true, data: record });
  } catch (err) {
    logger.error(`DNS add record error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/dns-mgmt/records/:domain
 * Get all DNS records for a domain
 */
router.get('/records/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const { type } = req.query;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    const records = dnsLib.getRecords(domain, type);

    return res.status(200).json({ 
      success: true, 
      domain,
      recordType: type || 'all',
      count: records.length,
      data: records 
    });
  } catch (err) {
    logger.error(`DNS get records error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/dns-mgmt/records/:domain/:recordId
 * Get a specific DNS record by ID
 */
router.get('/records/:domain/:recordId', async (req, res) => {
  try {
    const { domain, recordId } = req.params;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    const record = dnsLib.getRecordById(domain, recordId);

    if (!record) {
      return res.status(404).json({ error: `Record not found: ${recordId}` });
    }

    return res.status(200).json({ success: true, data: record });
  } catch (err) {
    logger.error(`DNS get record error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * PUT /api/dns-mgmt/records/:domain/:recordId
 * Update a DNS record
 */
router.put('/records/:domain/:recordId', async (req, res) => {
  try {
    const { domain, recordId } = req.params;
    const updates = req.body;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    const record = dnsLib.updateRecord(domain, recordId, updates);

    logger.info(`API: Updated record ${recordId} for ${domain}`);
    return res.status(200).json({ success: true, data: record });
  } catch (err) {
    logger.error(`DNS update record error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/dns-mgmt/records/:domain/:recordId
 * Delete a DNS record
 */
router.delete('/records/:domain/:recordId', async (req, res) => {
  try {
    const { domain, recordId } = req.params;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    dnsLib.deleteRecord(domain, recordId);

    logger.info(`API: Deleted record ${recordId} for ${domain}`);
    return res.status(200).json({ success: true, message: 'Record deleted' });
  } catch (err) {
    logger.error(`DNS delete record error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/dns-mgmt/records/:domain/bulk
 * Add multiple DNS records at once
 */
router.post('/records/:domain/bulk', async (req, res) => {
  try {
    const { domain } = req.params;
    const { records } = req.body;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    if (!Array.isArray(records)) {
      return res.status(400).json({ error: 'records must be an array' });
    }

    const result = dnsLib.addRecordsBulk(domain, records);

    logger.info(`API: Bulk added ${result.success.length} records for ${domain}`);
    return res.status(201).json({ 
      success: result.errors.length === 0, 
      created: result.success.length,
      errors: result.errors.length,
      data: result
    });
  } catch (err) {
    logger.error(`DNS bulk add error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/dns-mgmt/stats/:domain
 * Get DNS record statistics
 */
router.get('/stats/:domain', async (req, res) => {
  try {
    const { domain } = req.params;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    const stats = dnsLib.getStats(domain);

    return res.status(200).json({ success: true, domain, data: stats });
  } catch (err) {
    logger.error(`DNS stats error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/dns-mgmt/export/:domain
 * Export records as zone file
 */
router.get('/export/:domain', async (req, res) => {
  try {
    const { domain } = req.params;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    const zoneFile = dnsLib.exportZoneFile(domain);

    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${domain}.zone"`);
    return res.send(zoneFile);
  } catch (err) {
    logger.error(`DNS export error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/dns-mgmt/import/:domain
 * Import records from zone file
 */
router.post('/import/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const { zoneFile } = req.body;

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    if (!zoneFile || typeof zoneFile !== 'string') {
      return res.status(400).json({ error: 'zoneFile content is required' });
    }

    const result = dnsLib.importZoneFile(domain, zoneFile);

    logger.info(`API: Imported ${result.success} records for ${domain}`);
    return res.status(201).json({ 
      success: result.errors.length === 0,
      imported: result.success,
      errors: result.errors
    });
  } catch (err) {
    logger.error(`DNS import error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * DELETE /api/dns-mgmt/clear/:domain
 * Clear all records for a domain (be careful!)
 */
router.delete('/clear/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const { confirm } = req.query;

    if (confirm !== 'true') {
      return res.status(400).json({ 
        error: 'This action is destructive. Add ?confirm=true to proceed.',
        warning: 'This will delete ALL DNS records for the domain'
      });
    }

    if (!dnsLib.isValidDomain(domain)) {
      return res.status(400).json({ error: `Invalid domain format: ${domain}` });
    }

    dnsLib.clearDomain(domain);

    logger.warn(`API: Cleared all records for ${domain}`);
    return res.status(200).json({ success: true, message: `All records cleared for ${domain}` });
  } catch (err) {
    logger.error(`DNS clear error: ${err.message}`);
    return res.status(400).json({ success: false, error: err.message });
  }
});

module.exports = router;
