const dns = require('dns');

jest.mock('dns', () => ({
  promises: {
    resolveTxt: jest.fn(),
  },
}));

const { lookupDMARCRecord } = require('../services/dns');

describe('dns.js — DNS lookup helpers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('[NEGATIVE] returns null when DMARC TXT lookup is refused by the DNS resolver', async () => {
    dns.promises.resolveTxt.mockRejectedValue({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED 127.0.0.1:53' });

    const record = await lookupDMARCRecord('example.org');
    expect(record).toBeNull();
    expect(dns.promises.resolveTxt).toHaveBeenCalledWith('_dmarc.example.org');
  });
});
