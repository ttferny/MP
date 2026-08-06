const express = require('express');
const router = express.Router();
const { planDnsAutomation, applyDnsAutomation, getPersistedPlan } = require('../services/dnsAutomation');
const { loadAuditLog } = require('../services/persistentStore');
const { checkDnsPropagation } = require('../services/dns');
const { syncDnsRecords } = require('../services/dnsAutomationUpdateDelete');
const { planLiveDnsSync, applyLiveDnsSync } = require('../services/liveDnsSync');
const { createCloudflareDnsClient, setRuntimeConfig, getRuntimeConfig } = require('../services/cloudflareDns');
const logger = require('../utils/logger');

router.post('/plan', async (req, res) => {
  try {
    const { domain, desiredRecords } = req.body;
    const plan = await planDnsAutomation(domain, desiredRecords);
    res.json({ success: true, data: plan });
  } catch (err) {
    logger.error(`DNS automation plan error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/apply', async (req, res) => {
  try {
    const { domain, desiredRecords, dryRun } = req.body;
    const result = await applyDnsAutomation(domain, desiredRecords, { dryRun });
    res.json({ success: true, data: result });
  } catch (err) {
    logger.error(`DNS automation apply error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.get('/persisted-plan', async (req, res) => {
  try {
    const { domain } = req.query;
    if (!domain) {
      return res.status(400).json({ success: false, error: 'Domain is required' });
    }

    const persistedPlan = getPersistedPlan(domain);
    res.json({ success: true, data: persistedPlan });
  } catch (err) {
    logger.error(`DNS automation persisted plan error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.get('/audit-log', async (req, res) => {
  try {
    const auditLog = loadAuditLog();
    res.json({ success: true, data: auditLog });
  } catch (err) {
    logger.error(`DNS automation audit log error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.get('/provider-status', async (req, res) => {
  try {
    const runtimeConfig = getRuntimeConfig();
    let provider = runtimeConfig.providerMode || 'local-memory';
    let configured = false;

    try {
      createCloudflareDnsClient();
      provider = runtimeConfig.providerMode === 'cloudflare' ? 'cloudflare' : 'cloudflare';
      configured = true;
    } catch (err) {
      provider = 'local-memory';
      configured = false;
    }

    res.json({ success: true, data: { provider, configured, mode: runtimeConfig.providerMode || 'local-memory' } });
  } catch (err) {
    logger.error(`DNS automation provider status error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/save-config', async (req, res) => {
  try {
    const { providerMode, cloudflareApiToken, cloudflareZoneId } = req.body;
    const config = setRuntimeConfig({
      providerMode: providerMode || 'local-memory',
      cloudflareApiToken: cloudflareApiToken || '',
      cloudflareZoneId: cloudflareZoneId || '',
    });

    res.json({ success: true, data: config });
  } catch (err) {
    logger.error(`DNS automation save config error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/sync', async (req, res) => {
  try {
    const { domain, desiredRecords } = req.body;
    const result = await syncDnsRecords(domain, desiredRecords);
    res.json({ success: true, data: result });
  } catch (err) {
    logger.error(`DNS automation sync error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/live-sync-plan', async (req, res) => {
  try {
    const { domain, desiredRecords } = req.body;
    const result = await planLiveDnsSync(domain, desiredRecords);
    res.json({ success: true, data: result });
  } catch (err) {
    logger.error(`DNS live sync plan error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/live-sync-apply', async (req, res) => {
  try {
    const { domain, desiredRecords, dryRun } = req.body;
    const result = await applyLiveDnsSync(domain, desiredRecords, { dryRun });
    res.json({ success: true, data: result });
  } catch (err) {
    logger.error(`DNS live sync apply error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/propagation-check', async (req, res) => {
  try {
    const { domain, recordName, expectedValue, recordType } = req.body;
    const result = await checkDnsPropagation(domain, recordName, expectedValue, recordType);
    res.json({ success: true, data: result });
  } catch (err) {
    logger.error(`DNS propagation check error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/test-connection', async (req, res) => {
  try {
    const { cloudflareApiToken, cloudflareZoneId } = req.body;
    const client = createCloudflareDnsClient({
      apiToken: cloudflareApiToken,
      zoneId: cloudflareZoneId,
    });
    const records = await client.listRecords();
    res.json({ success: true, data: { zoneName: cloudflareZoneId || 'configured', recordCount: records.length } });
  } catch (err) {
    logger.error(`DNS automation test connection error: ${err.message}`);
    res.status(400).json({ success: false, error: err.message });
  }
});

module.exports = router;
