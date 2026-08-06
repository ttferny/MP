const path = require('path');
const fs = require('fs');
const dnsLibrary = require('../services/dnsLibrary');
const dnsAutomation = require('../services/dnsAutomation');
const { loadAuditLog } = require('../services/persistentStore');

const storageDir = path.join(__dirname, '..', 'data');
const dnsStoreFile = path.join(storageDir, 'dns-library.json');
const auditFile = path.join(storageDir, 'automation-audit.json');

beforeEach(() => {
  dnsLibrary.clearDomain('persist-test.example');
  if (fs.existsSync(dnsStoreFile)) {
    fs.rmSync(dnsStoreFile, { force: true });
  }
  if (fs.existsSync(auditFile)) {
    fs.rmSync(auditFile, { force: true });
  }
});

afterEach(() => {
  dnsLibrary.clearDomain('persist-test.example');
  if (fs.existsSync(dnsStoreFile)) {
    fs.rmSync(dnsStoreFile, { force: true });
  }
  if (fs.existsSync(auditFile)) {
    fs.rmSync(auditFile, { force: true });
  }
});

test('persists DNS records to disk so they survive a module reload', async () => {
  dnsLibrary.addRecord('persist-test.example', 'TXT', {
    name: '',
    content: 'v=spf1 a mx -all',
    ttl: 3600,
  });

  jest.resetModules();
  const reloadedDnsLibrary = require('../services/dnsLibrary');
  const records = reloadedDnsLibrary.getRecords('persist-test.example');

  expect(records).toHaveLength(1);
  expect(records[0].content).toBe('v=spf1 a mx -all');
});

test('records automation plan and apply actions in the audit log', async () => {
  await dnsAutomation.planDnsAutomation('persist-test.example', [
    { type: 'TXT', name: '', content: 'v=spf1 a mx -all', ttl: 3600 },
  ]);

  const auditLog = loadAuditLog();
  expect(auditLog.length).toBeGreaterThan(0);
  expect(auditLog.some((entry) => entry.kind === 'plan')).toBe(true);
});
