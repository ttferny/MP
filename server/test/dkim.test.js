const { verifyDKIM } = require('../services/dkim');

jest.mock('../services/dns', () => ({
  lookupDKIMRecord: jest.fn(),
}));

const { lookupDKIMRecord } = require('../services/dns');

describe('dkim.js — verifyDKIM()', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('[POSITIVE] passes when DKIM signature is present and DNS key exists', async () => {
    lookupDKIMRecord.mockResolvedValue('v=DKIM1; k=rsa; p=mockkey');

    const parsed = {
      dkimSignature: {
        v: '1',
        a: 'rsa-sha256',
        d: 'company.com',
        s: 'mail',
        h: 'from:subject',
        bh: 'abc123',
        b: 'signature',
      },
    };

    const result = await verifyDKIM(parsed);

    expect(result.status).toBe('pass');
    expect(result.domain).toBe('company.com');
    expect(result.selector).toBe('mail');
    expect(result.dnsRecord).toBe('v=DKIM1; k=rsa; p=mockkey');
  });

  test('[NEGATIVE] returns none when no DKIM signature is present', async () => {
    const parsed = { dkimSignature: {} };
    const result = await verifyDKIM(parsed);

    expect(result.status).toBe('none');
    expect(result.reason).toMatch(/no DKIM signature/i);
  });

  test('[NEGATIVE] fails when selector or domain is missing', async () => {
    const parsed = { dkimSignature: { d: 'company.com' } };
    const result = await verifyDKIM(parsed);

    expect(result.status).toBe('fail');
    expect(result.reason).toMatch(/missing d= or s=/i);
  });

  test('[NEGATIVE] fails when DNS key is not found', async () => {
    lookupDKIMRecord.mockResolvedValue(null);

    const parsed = {
      dkimSignature: {
        v: '1',
        a: 'rsa-sha256',
        d: 'company.com',
        s: 'mail',
        h: 'from:subject',
        bh: 'abc123',
        b: 'signature',
      },
    };

    const result = await verifyDKIM(parsed);

    expect(result.status).toBe('fail');
    expect(result.reason).toMatch(/public key not found/i);
  });
});
