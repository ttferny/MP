const logger = require('../utils/logger');

let runtimeConfig = {
  providerMode: 'local-memory',
  cloudflareApiToken: process.env.CLOUDFLARE_API_TOKEN || '',
  cloudflareZoneId: process.env.CLOUDFLARE_ZONE_ID || '',
};

function setRuntimeConfig(config = {}) {
  runtimeConfig = {
    ...runtimeConfig,
    ...config,
  };
  return runtimeConfig;
}

function getRuntimeConfig() {
  return { ...runtimeConfig };
}

function createCloudflareDnsClient(options = {}) {
  const apiToken = options.apiToken || runtimeConfig.cloudflareApiToken || process.env.CLOUDFLARE_API_TOKEN;
  const zoneId = options.zoneId || runtimeConfig.cloudflareZoneId || process.env.CLOUDFLARE_ZONE_ID;

  if (!apiToken || !zoneId) {
    throw new Error('Cloudflare credentials are not configured. Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID.');
  }

  const baseUrl = 'https://api.cloudflare.com/client/v4/zones';

  async function request(path, init = {}) {
    const response = await fetch(`${baseUrl}/${zoneId}${path}`, {
      ...init,
      headers: {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type': 'application/json',
        ...(init.headers || {}),
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Cloudflare API error: ${errorText}`);
    }

    return response.json();
  }

  async function listRecords() {
    const payload = await request('/dns_records');
    return (payload.result || []).map((record) => ({
      id: record.id,
      type: record.type,
      name: record.name,
      content: record.content,
      ttl: record.ttl,
      priority: record.priority || null,
      proxied: record.proxied || false,
      raw: record,
    }));
  }

  async function createRecord(record) {
    const payload = await request('/dns_records', {
      method: 'POST',
      body: JSON.stringify({
        type: record.type,
        name: record.name,
        content: record.content,
        ttl: record.ttl || 300,
        priority: record.priority || undefined,
      }),
    });

    logger.info(`Cloudflare DNS create: ${record.type} ${record.name}`);
    return payload.result;
  }

  async function updateRecord(recordId, record) {
    const payload = await request(`/dns_records/${recordId}`, {
      method: 'PUT',
      body: JSON.stringify({
        type: record.type,
        name: record.name,
        content: record.content,
        ttl: record.ttl || 300,
        priority: record.priority || undefined,
      }),
    });

    logger.info(`Cloudflare DNS update: ${record.type} ${record.name}`);
    return payload.result;
  }

  async function deleteRecord(recordId) {
    const payload = await request(`/dns_records/${recordId}`, { method: 'DELETE' });
    logger.info(`Cloudflare DNS delete: ${recordId}`);
    return payload;
  }

  return {
    listRecords,
    createRecord,
    updateRecord,
    deleteRecord,
  };
}

module.exports = {
  createCloudflareDnsClient,
  setRuntimeConfig,
  getRuntimeConfig,
};
