const dnsAutomation = require('../services/dnsAutomation');

jest.mock('../services/dns', () => ({
  lookupSPFRecord: jest.fn(),
  lookupDMARCRecord: jest.fn(),
  lookupDKIMRecord: jest.fn(),
  lookupTxtRecords: jest.fn(),
  lookupARecords: jest.fn(),
  lookupMXRecords: jest.fn(),
}));

jest.mock('../services/dnsLibrary', () => ({
  addRecord: jest.fn(),
  getRecords: jest.fn(),
  updateRecord: jest.fn(),
  isValidDomain: jest.fn((domain) => /^[a-z0-9.-]+$/i.test(domain)),
}));

const { lookupTxtRecords, lookupSPFRecord, lookupDMARCRecord } = require('../services/dns');
const dnsLibrary = require('../services/dnsLibrary');

beforeEach(() => {
  jest.clearAllMocks();
});

test('planDnsAutomation flags missing SPF and DMARC records', async () => {
  lookupTxtRecords.mockResolvedValue([]);

  const plan = await dnsAutomation.planDnsAutomation('example.com', [
    { type: 'TXT', name: '', content: 'v=spf1 a mx -all', ttl: 3600 },
    { type: 'TXT', name: '_dmarc', content: 'v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com', ttl: 3600 },
  ]);

  expect(plan.summary.missingCount).toBe(2);
  expect(plan.changes[0].action).toBe('create');
  expect(plan.changes[0].record.name).toBe('');
});

test('applyDnsAutomation adds missing records when dryRun is false', async () => {
  lookupTxtRecords.mockResolvedValue([]);
  dnsLibrary.getRecords.mockReturnValue([]);
  dnsLibrary.addRecord.mockReturnValue({ id: '1', type: 'TXT' });

  const result = await dnsAutomation.applyDnsAutomation('example.com', [
    { type: 'TXT', name: '', content: 'v=spf1 a mx -all', ttl: 3600 },
  ], { dryRun: false });

  expect(result.applied.length).toBe(1);
  expect(dnsLibrary.addRecord).toHaveBeenCalled();
});

test('planDnsAutomation plans an update when an existing local TXT differs from the desired value', async () => {
  lookupTxtRecords.mockResolvedValue(['v=spf1 include:_spf.example.com ~all']);
  dnsLibrary.getRecords.mockReturnValue([{ id: '1', type: 'TXT', name: '', content: 'v=spf1 a mx -all' }]);

  const plan = await dnsAutomation.planDnsAutomation('example.com', [
    { type: 'TXT', name: '', content: 'v=spf1 include:_spf.example.com ~all', ttl: 3600 },
  ]);

  expect(plan.changes[0].action).toBe('update');
});

test('planDnsAutomation plans a delete for managed records that are no longer desired', async () => {
  lookupTxtRecords.mockResolvedValue([]);
  dnsLibrary.getRecords.mockReturnValue([{ id: '2', type: 'TXT', name: '', content: 'v=spf1 a mx -all', managedByDesiredState: true }]);

  const plan = await dnsAutomation.planDnsAutomation('example.com', []);

  expect(plan.changes[0].action).toBe('delete');
});

test('planDnsAutomation marks live SPF as an update instead of creating a second SPF record', async () => {
  lookupSPFRecord.mockResolvedValue('v=spf1 ip4:20.33.0.0/16 include:spf.protection.outlook.com -all');
  lookupDMARCRecord.mockResolvedValue(null);
  dnsLibrary.getRecords.mockReturnValue([]);

  const plan = await dnsAutomation.planDnsAutomation('example.com', [
    { type: 'TXT', name: '', content: 'v=spf1 a mx -all', ttl: 3600, purpose: 'spf' },
  ]);

  expect(plan.changes).toHaveLength(1);
  expect(plan.changes[0].action).toBe('update');
  expect(plan.changes[0].currentValue).toContain('include:spf.protection.outlook.com');
  expect(plan.changes[0].reason).toContain('differs from recommended policy');
});

test('planDnsAutomation uses existing parsed DNS records when provided instead of relying on a separate lookup', async () => {
  dnsLibrary.getRecords.mockReturnValue([]);

  const plan = await dnsAutomation.planDnsAutomation(
    'example.com',
    [{ type: 'TXT', name: '', content: 'v=spf1 a mx -all', ttl: 3600, purpose: 'spf' }],
    {
      existingRecords: {
        spf: {
          status: 'found',
          record: 'v=spf1 include:_spf.example.com ~all',
        },
      },
    }
  );

  expect(plan.changes).toHaveLength(1);
  expect(plan.changes[0].action).toBe('update');
  expect(plan.changes[0].currentValue).toBe('v=spf1 include:_spf.example.com ~all');
  expect(lookupSPFRecord).not.toHaveBeenCalled();
});
