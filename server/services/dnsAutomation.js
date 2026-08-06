const dns = require('./dns');
const dnsLibrary = require('./dnsLibrary');
const { createCloudflareDnsClient } = require('./cloudflareDns');
const logger = require('../utils/logger');
const { appendAuditEntry } = require('./persistentStore');

const DEFAULT_DESIRED_RECORDS = [
  {
    type: 'TXT',
    name: '',
    content: 'v=spf1 a mx -all',
    ttl: 3600,
    purpose: 'spf',
  },
  {
    type: 'TXT',
    name: '_dmarc',
    content: 'v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com',
    ttl: 3600,
    purpose: 'dmarc',
  },
];

let persistedPlans = {};

function normalizeRecord(record) {
  return {
    type: (record.type || 'TXT').toUpperCase(),
    name: record.name || '',
    content: record.content || record.target || '',
    ttl: record.ttl || 3600,
    priority: record.priority || null,
    weight: record.weight || null,
    port: record.port || null,
    flag: record.flag || null,
    tag: record.tag || null,
    purpose: record.purpose || null,
  };
}

function recordMatchesDesired(record, desired) {
  if (!record || !desired) {
    return false;
  }

  return record.type === desired.type
    && String(record.name || '') === String(desired.name || '')
    && String(record.content || record.target || '') === String(desired.content || '');
}

function persistPlan(domain, plan) {
  persistedPlans[domain] = {
    domain,
    createdAt: new Date().toISOString(),
    plan,
  };
  return persistedPlans[domain];
}

function getPersistedPlan(domain) {
  return persistedPlans[domain] || null;
}

function clearPersistedPlan(domain) {
  delete persistedPlans[domain];
}

async function lookupWithFallback(lookupFn, domain) {
  if (typeof lookupFn !== 'function') {
    return null;
  }

  try {
    return await lookupFn(domain);
  } catch (err) {
    logger.warn(`DNS lookup failed for ${domain}: ${err.message}`);
    return null;
  }
}

function getProviderClient() {
  try {
    return createCloudflareDnsClient();
  } catch (err) {
    return null;
  }
}

async function planDnsAutomation(domain, desiredRecords = DEFAULT_DESIRED_RECORDS) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain is required');
  }

  if (!dnsLibrary.isValidDomain(domain)) {
    throw new Error('Invalid domain format');
  }

  const normalizedDesired = (desiredRecords || []).map(normalizeRecord);
  const providerClient = getProviderClient();
  const existingRecords = providerClient ? await providerClient.listRecords().catch(() => []) : (dnsLibrary.getRecords(domain) || []);
  const changes = [];

  const desiredKeys = new Set(normalizedDesired.map((record) => `${record.type}:${String(record.name || '')}:${String(record.content || '')}`));

  const managedRecords = existingRecords.filter((record) => record.managedByDesiredState || record.source === 'desired-state' || record.purpose);

  for (const desired of normalizedDesired) {
    const desiredKey = `${desired.type}:${String(desired.name || '')}:${String(desired.content || '')}`;
    const existing = existingRecords.find((record) => `${record.type}:${String(record.name || '')}:${String(record.content || record.target || '')}` === desiredKey);

    if (!existing) {
      const sameNameRecord = existingRecords.find((record) => record.type === desired.type && String(record.name || '') === String(desired.name || ''));
      if (sameNameRecord) {
        changes.push({
          action: 'update',
          record: desired,
          reason: `${desired.purpose || desired.type} record differs from desired state`,
          currentValue: sameNameRecord.content || sameNameRecord.target || '',
          existingRecord: sameNameRecord,
        });
      } else {
        changes.push({
          action: 'create',
          record: desired,
          reason: `${desired.purpose || desired.type} record missing`,
        });
      }
    }
  }

  for (const existing of managedRecords) {
    const existingKey = `${existing.type}:${String(existing.name || '')}:${String(existing.content || existing.target || '')}`;
    if (!desiredKeys.has(existingKey)) {
      changes.push({
        action: 'delete',
        record: normalizeRecord(existing),
        reason: `${existing.type} record is no longer desired`,
        existingRecord: existing,
      });
    }
  }

  const liveSpf = await lookupWithFallback(dns.lookupSPFRecord, domain);
  const liveDmarc = await lookupWithFallback(dns.lookupDMARCRecord, domain);

  const summary = {
    desiredCount: normalizedDesired.length,
    existingCount: existingRecords.length,
    createCount: changes.filter((change) => change.action === 'create').length,
    missingCount: changes.filter((change) => change.action === 'create').length,
    updateCount: changes.filter((change) => change.action === 'update').length,
    deleteCount: changes.filter((change) => change.action === 'delete').length,
    hasSpf: Boolean(liveSpf),
    hasDmarc: Boolean(liveDmarc),
    provider: providerClient ? 'cloudflare' : 'local-memory',
  };

  const plan = { domain, summary, changes };
  persistPlan(domain, plan);
  appendAuditEntry({ kind: 'plan', domain, summary, changes });
  return plan;
}

async function applyDnsAutomation(domain, desiredRecords = DEFAULT_DESIRED_RECORDS, options = {}) {
  const plan = await planDnsAutomation(domain, desiredRecords);
  const dryRun = options.dryRun !== false;
  const applied = [];

  if (dryRun) {
    return { domain, dryRun: true, plan, applied: [] };
  }

  const providerClient = getProviderClient();

  for (const change of plan.changes) {
    let created;

    if (providerClient) {
      if (change.action === 'update') {
        const existing = (await providerClient.listRecords().catch(() => [])).find((record) => record.type === change.record.type && String(record.name || '') === String(change.record.name || ''));
        if (existing) {
          created = await providerClient.updateRecord(existing.id, {
            type: change.record.type,
            name: change.record.name,
            content: change.record.content,
            ttl: change.record.ttl,
          });
        } else {
          created = await providerClient.createRecord({
            type: change.record.type,
            name: change.record.name,
            content: change.record.content,
            ttl: change.record.ttl,
          });
        }
      } else if (change.action === 'delete') {
        const existing = (await providerClient.listRecords().catch(() => [])).find((record) => record.type === change.record.type && String(record.name || '') === String(change.record.name || ''));
        if (existing) {
          await providerClient.deleteRecord(existing.id);
          created = { deleted: true, id: existing.id };
        }
      } else {
        created = await providerClient.createRecord({
          type: change.record.type,
          name: change.record.name,
          content: change.record.content,
          ttl: change.record.ttl,
        });
      }
    } else {
      const localRecords = dnsLibrary.getRecords(domain) || [];
      const existing = localRecords.find((record) => record.type === change.record.type && String(record.name || '') === String(change.record.name || ''));
      if (change.action === 'update' && existing) {
        created = dnsLibrary.updateRecord(domain, existing.id, {
          content: change.record.content,
          ttl: change.record.ttl,
          managedByDesiredState: true,
          source: 'desired-state',
        });
      } else if (change.action === 'delete' && existing) {
        dnsLibrary.deleteRecord(domain, existing.id);
        created = { deleted: true, id: existing.id };
      } else {
        created = dnsLibrary.addRecord(domain, change.record.type, {
          name: change.record.name,
          content: change.record.content,
          ttl: change.record.ttl,
          priority: change.record.priority,
          weight: change.record.weight,
          port: change.record.port,
          flag: change.record.flag,
          tag: change.record.tag,
          managedByDesiredState: true,
          source: 'desired-state',
        });
      }
    }

    applied.push(created);
    logger.info(`Applied DNS automation change for ${domain}: ${change.record.type}`);
  }

  clearPersistedPlan(domain);
  const completedPlan = { ...plan, appliedAt: new Date().toISOString() };
  persistPlan(domain, completedPlan);
  appendAuditEntry({ kind: 'apply', domain, summary: completedPlan.summary, applied, dryRun: false });
  return { domain, dryRun: false, plan: completedPlan, applied };
}

module.exports = {
  planDnsAutomation,
  applyDnsAutomation,
  DEFAULT_DESIRED_RECORDS,
  getPersistedPlan,
  clearPersistedPlan,
};
