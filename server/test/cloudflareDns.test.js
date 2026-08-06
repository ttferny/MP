const { createCloudflareDnsClient } = require('../services/cloudflareDns');

describe('Cloudflare DNS client', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    process.env.CLOUDFLARE_API_TOKEN = 'token-123';
    process.env.CLOUDFLARE_ZONE_ID = 'zone-123';
    global.fetch = jest.fn();
  });

  afterEach(() => {
    delete process.env.CLOUDFLARE_API_TOKEN;
    delete process.env.CLOUDFLARE_ZONE_ID;
  });

  test('lists records from Cloudflare and normalizes them', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        result: [{ id: 'abc', type: 'TXT', name: '@', content: 'v=spf1 a mx -all', ttl: 3600 }],
      }),
    });

    const client = createCloudflareDnsClient();
    const records = await client.listRecords();

    expect(records).toHaveLength(1);
    expect(records[0]).toEqual(expect.objectContaining({ id: 'abc', type: 'TXT', name: '@' }));
    expect(global.fetch).toHaveBeenCalled();
  });

  test('creates a record using the Cloudflare API', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ result: { id: 'new-id' } }),
    });

    const client = createCloudflareDnsClient();
    const created = await client.createRecord({ type: 'TXT', name: '_dmarc', content: 'v=DMARC1', ttl: 300 });

    expect(created).toEqual(expect.objectContaining({ id: 'new-id' }));
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.cloudflare.com/client/v4/zones/zone-123/dns_records',
      expect.objectContaining({ method: 'POST' })
    );
  });
});
