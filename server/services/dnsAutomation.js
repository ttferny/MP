const dns = require('./dns');
const dnsLibrary = require('./dnsLibrary');
const { createCloudflareDnsClient } = require('./cloudflareDns');
const logger = require('../utils/logger');

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

  for (const desired of normalizedDesired) {
    const match = existingRecords.find((record) => {
      const sameType = record.type === desired.type;
      const sameName = String(record.name || '') === String(desired.name || '');
      const sameContent = String(record.content || '') === String(desired.content || '');
      return sameType && sameName && sameContent;
    });

    if (!match) {
      changes.push({
        action: 'create',
        record: desired,
        reason: `${desired.purpose || desired.type} record missing`,
      });
    }
  }

  const liveSpf = await lookupWithFallback(dns.lookupSPFRecord, domain);
  const liveDmarc = await lookupWithFallback(dns.lookupDMARCRecord, domain);

  const summary = {
    desiredCount: normalizedDesired.length,
    existingCount: existingRecords.length,
    missingCount: changes.length,
    hasSpf: Boolean(liveSpf),
    hasDmarc: Boolean(liveDmarc),
    provider: providerClient ? 'cloudflare' : 'local-memory',
  };

  return { domain, summary, changes };
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
      created = await providerClient.createRecord({
        type: change.record.type,
        name: change.record.name,
        content: change.record.content,
        ttl: change.record.ttl,
      });
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
      });
    }

    applied.push(created);
    logger.info(`Applied DNS automation change for ${domain}: ${change.record.type}`);
  }

  return { domain, dryRun: false, plan, applied };
}

module.exports = {
  planDnsAutomation,
  applyDnsAutomation,
  DEFAULT_DESIRED_RECORDS,
};
