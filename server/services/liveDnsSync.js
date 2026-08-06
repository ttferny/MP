const dns = require('./dns');
const dnsLibrary = require('./dnsLibrary');
const { createCloudflareDnsClient } = require('./cloudflareDns');
const logger = require('../utils/logger');

function normalizeDesiredRecord(record) {
  return {
    type: (record.type || 'TXT').toUpperCase(),
    name: record.name || '',
    content: record.content || record.target || '',
    ttl: record.ttl || 300,
    purpose: record.purpose || null,
  };
}

function buildRecordName(domain, name) {
  if (!name || name === '@' || name === '') {
    return domain;
  }

  if (String(name).endsWith(domain)) {
    return name;
  }

  return `${name}.${domain}`;
}

function getProviderClient() {
  try {
    return createCloudflareDnsClient();
  } catch (err) {
    return null;
  }
}

async function planLiveDnsSync(domain, desiredRecords = []) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain is required');
  }

  if (!dnsLibrary.isValidDomain(domain)) {
    throw new Error('Invalid domain format');
  }

  const normalizedDesired = (desiredRecords || []).map(normalizeDesiredRecord);
  const changes = [];
  const records = [];

  for (const desired of normalizedDesired) {
    if (desired.type !== 'TXT') {
      continue;
    }

    const fqdn = buildRecordName(domain, desired.name);
    const liveRecords = await dns.lookupTxtRecords(fqdn).catch(() => []);
    const hasMatch = liveRecords.some((record) => String(record) === String(desired.content));

    if (!hasMatch) {
      const action = liveRecords.length > 0 ? 'update' : 'create';
      changes.push({
        action,
        record: desired,
        fqdn,
        liveRecords,
      });
      records.push({
        fqdn,
        record: desired,
        status: 'outdated',
        action,
        liveRecords,
      });
    } else {
      records.push({
        fqdn,
        record: desired,
        status: 'matching',
        action: 'none',
        liveRecords,
      });
    }
  }

  return {
    domain,
    summary: {
      desiredCount: normalizedDesired.length,
      changesCount: changes.length,
      provider: getProviderClient() ? 'cloudflare' : 'local-memory',
    },
    records,
    changes,
  };
}

async function applyLiveDnsSync(domain, desiredRecords = [], options = {}) {
  const plan = await planLiveDnsSync(domain, desiredRecords);
  const dryRun = options.dryRun !== false;
  const applied = [];

  if (dryRun) {
    return { domain, dryRun: true, plan, applied: [] };
  }

  const providerClient = getProviderClient();
  const providerRecords = providerClient ? await providerClient.listRecords().catch(() => []) : [];
  const localRecords = dnsLibrary.getRecords(domain) || [];

  for (const change of plan.changes) {
    if (providerClient) {
      const providerMatch = providerRecords.find((record) => String(record.name || '') === String(change.record.name || '') && record.type === change.record.type && String(record.content || '') === String(change.record.content || ''));
      const created = change.action === 'update' && providerMatch
        ? await providerClient.updateRecord(providerMatch.id, {
            type: change.record.type,
            name: change.record.name,
            content: change.record.content,
            ttl: change.record.ttl,
          })
        : await providerClient.createRecord({
            type: change.record.type,
            name: change.record.name,
            content: change.record.content,
            ttl: change.record.ttl,
          });
      applied.push(created);
    } else {
      const localMatch = localRecords.find((record) => String(record.name || '') === String(change.record.name || '') && record.type === change.record.type && String(record.content || '') === String(change.record.content || ''));
      const created = change.action === 'update' && localMatch
        ? dnsLibrary.updateRecord(domain, localMatch.id, {
            content: change.record.content,
            ttl: change.record.ttl,
          })
        : dnsLibrary.addRecord(domain, change.record.type, {
            name: change.record.name,
            content: change.record.content,
            ttl: change.record.ttl,
          });
      applied.push(created);
    }

    logger.info(`Applied live DNS sync change for ${domain}: ${change.record.type}`);
  }

  return { domain, dryRun: false, plan, applied };
}

module.exports = {
  planLiveDnsSync,
  applyLiveDnsSync,
};
