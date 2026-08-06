const dnsLibrary = require('./dnsLibrary');
const { createCloudflareDnsClient } = require('./cloudflareDns');
const logger = require('../utils/logger');

async function syncDnsRecords(domain, desiredRecords, options = {}) {
  const providerClient = getProviderClient();
  const currentRecords = providerClient ? await providerClient.listRecords().catch(() => []) : (dnsLibrary.getRecords(domain) || []);
  const desired = (desiredRecords || []).map((record) => ({
    type: (record.type || 'TXT').toUpperCase(),
    name: record.name || '',
    content: record.content || record.target || '',
    ttl: record.ttl || 300,
  }));

  const toCreate = [];
  const toUpdate = [];
  const toDelete = [];

  for (const desiredRecord of desired) {
    const existing = currentRecords.find((record) => String(record.name || '') === String(desiredRecord.name || '') && record.type === desiredRecord.type && String(record.content || '') === String(desiredRecord.content || ''));
    if (!existing) {
      toCreate.push(desiredRecord);
    }
  }

  if (providerClient) {
    for (const change of toCreate) {
      await providerClient.createRecord(change);
      logger.info(`Cloudflare sync create: ${change.type} ${change.name}`);
    }
  } else {
    for (const change of toCreate) {
      dnsLibrary.addRecord(domain, change.type, change);
      logger.info(`Local sync create: ${change.type} ${change.name}`);
    }
  }

  return {
    domain,
    created: toCreate.length,
    updated: toUpdate.length,
    deleted: toDelete.length,
    provider: providerClient ? 'cloudflare' : 'local-memory',
  };
}

function getProviderClient() {
  try {
    return createCloudflareDnsClient();
  } catch (err) {
    return null;
  }
}

module.exports = { syncDnsRecords };
