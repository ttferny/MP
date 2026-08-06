const dns = require('../services/dns');
const dnsLibrary = require('../services/dnsLibrary');
const { planLiveDnsSync, applyLiveDnsSync } = require('../services/liveDnsSync');

jest.mock('../services/dns', () => ({
  lookupTxtRecords: jest.fn(),
  lookupSPFRecord: jest.fn(),
  lookupDMARCRecord: jest.fn(),
  lookupDKIMRecord: jest.fn(),
  lookupARecords: jest.fn(),
  lookupMXRecords: jest.fn(),
}));

jest.mock('../services/dnsLibrary', () => ({
  addRecord: jest.fn(),
  getRecords: jest.fn(),
  updateRecord: jest.fn(),
  isValidDomain: jest.fn((domain) => /^[a-z0-9.-]+$/i.test(domain)),
}));

jest.mock('../services/cloudflareDns', () => ({
  createCloudflareDnsClient: jest.fn(() => null),
}));

beforeEach(() => {
  jest.clearAllMocks();
});

test('planLiveDnsSync reports an update when live TXT content differs', async () => {
  dns.lookupTxtRecords.mockResolvedValue(['v=spf1 a mx -all']);

  const plan = await planLiveDnsSync('example.com', [
    { type: 'TXT', name: '', content: 'v=spf1 include:_spf.example.com ~all' },
  ]);

  expect(plan.summary.changesCount).toBe(1);
  expect(plan.changes[0].action).toBe('update');
  expect(plan.records[0].status).toBe('outdated');
  expect(plan.records[0].action).toBe('update');
});

test('applyLiveDnsSync writes a record when dryRun is false', async () => {
  dns.lookupTxtRecords.mockResolvedValue([]);
  dnsLibrary.getRecords.mockReturnValue([]);
  dnsLibrary.addRecord.mockReturnValue({ id: '1', type: 'TXT' });

  const result = await applyLiveDnsSync('example.com', [
    { type: 'TXT', name: '', content: 'v=spf1 a mx -all' },
  ], { dryRun: false });

  expect(result.applied).toHaveLength(1);
  expect(dnsLibrary.addRecord).toHaveBeenCalled();
});
