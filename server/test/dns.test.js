const dns = require('dns');

jest.mock('dns', () => ({
  promises: {
    resolveTxt: jest.fn(),
  },
}));

const { lookupDMARCRecord, lookupDKIMRecord } = require('../services/dns');

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

  test('[POSITIVE] returns DKIM TXT record when record starts with k=rsa and omits v=', async () => {
    dns.promises.resolveTxt.mockResolvedValue([['k=rsa; p=mockkey']]);

    const record = await lookupDKIMRecord('example.org', 'mail');
    expect(record).toBe('k=rsa; p=mockkey');
    expect(dns.promises.resolveTxt).toHaveBeenCalledWith('mail._domainkey.example.org');
  });
});
