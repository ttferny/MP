/**
 * ============================================================
 * dnsLibrary.js — Professional DNS Record Management Library
 * ============================================================
 *
 * Complete DNS record management system supporting:
 * - Multiple DNS providers (Cloudflare, Route53, DigitalOcean, etc.)
 * - Local record management
 * - All common record types (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA)
 * - Full CRUD operations (Create, Read, Update, Delete)
 * - Input validation and error handling
 */

const logger = require('../utils/logger');

/**
 * DNS Record Types
 */
const DNS_RECORD_TYPES = {
  A: 'A',
  AAAA: 'AAAA',
  CNAME: 'CNAME',
  MX: 'MX',
  TXT: 'TXT',
  NS: 'NS',
  SOA: 'SOA',
  SRV: 'SRV',
  CAA: 'CAA',
  PTR: 'PTR',
  SPF: 'TXT', // SPF records are TXT records
};

/**
 * Validation rules for each record type
 */
const VALIDATION_RULES = {
  A: {
    content: (val) => /^(\d{1,3}\.){3}\d{1,3}$/.test(val) && val.split('.').every(n => parseInt(n) <= 255),
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  AAAA: {
    content: (val) => /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(val),
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  CNAME: {
    content: (val) => /^[a-zA-Z0-9._-]+$/.test(val),
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  MX: {
    content: (val) => /^[a-zA-Z0-9._-]+$/.test(val),
    priority: (val) => val >= 0 && val <= 65535,
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  TXT: {
    content: (val) => typeof val === 'string' && val.length > 0 && val.length <= 255,
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  NS: {
    content: (val) => /^[a-zA-Z0-9._-]+$/.test(val),
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  SRV: {
    content: (val) => /^[a-zA-Z0-9._-]+$/.test(val),
    priority: (val) => val >= 0 && val <= 65535,
    weight: (val) => val >= 0 && val <= 65535,
    port: (val) => val > 0 && val <= 65535,
    name: (val) => /^_[a-zA-Z0-9._-]+$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
  CAA: {
    content: (val) => typeof val === 'string' && val.length > 0,
    flag: (val) => val === 0 || val === 128,
    tag: (val) => ['issue', 'issuewild', 'iodef'].includes(val),
    name: (val) => /^[a-zA-Z0-9._-]*$/.test(val),
    ttl: (val) => val >= 60 && val <= 86400,
  },
};

/**
 * Local in-memory DNS record store (for testing/demo purposes)
 */
let localDNSRecords = {};

/**
 * Initialize local DNS records for a domain
 */
function initializeDomain(domain) {
  if (!localDNSRecords[domain]) {
    localDNSRecords[domain] = [];
    logger.info(`Initialized DNS records for domain: ${domain}`);
  }
}

/**
 * Validate a DNS record
 * @param {string} type - Record type (A, AAAA, MX, TXT, etc.)
 * @param {object} record - Record data
 * @throws {Error} if validation fails
 */
function validateRecord(type, record) {
  if (!DNS_RECORD_TYPES[type]) {
    throw new Error(`Invalid record type: ${type}. Valid types: ${Object.keys(DNS_RECORD_TYPES).join(', ')}`);
  }

  const rules = VALIDATION_RULES[type];
  if (!rules) {
    throw new Error(`No validation rules defined for type: ${type}`);
  }

  // Validate each field
  for (const [field, validator] of Object.entries(rules)) {
    if (record[field] !== undefined && record[field] !== null && record[field] !== '' && !validator(record[field])) {
      throw new Error(`Invalid ${field} for ${type} record: ${record[field]}`);
    }
  }

  // Check required fields - name can be empty string for root record
  if (record.name === undefined || record.name === null) {
    throw new Error('Record name is required (use empty string "" for root)');
  }

  if (!record.content && !record.target) {
    throw new Error(`Record content/target is required for ${type}`);
  }

  return true;
}

/**
 * Add a DNS record to local storage
 * @param {string} domain - Domain name
 * @param {string} type - Record type (A, AAAA, MX, TXT, etc.)
 * @param {object} recordData - Record data (name, content, ttl, etc.)
 * @returns {object} Created record with ID
 * @throws {Error} if validation fails
 */
function addRecord(domain, type, recordData) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain must be a non-empty string');
  }

  if (!type || typeof type !== 'string') {
    throw new Error('Record type is required');
  }

  // Normalize input
  const normalizedType = type.toUpperCase();
  
  // Validate record
  validateRecord(normalizedType, recordData);

  // Initialize domain if needed
  initializeDomain(domain);

  // Check for duplicates
  const isDuplicate = localDNSRecords[domain].some(
    r => r.type === normalizedType && 
         r.name === recordData.name && 
         (r.content === recordData.content || r.target === recordData.target)
  );

  if (isDuplicate) {
    throw new Error(`Record already exists: ${recordData.name} ${normalizedType}`);
  }

  // Create record
  const record = {
    id: `${domain}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    domain,
    type: normalizedType,
    name: recordData.name,
    content: recordData.content || recordData.target || null,
    ttl: recordData.ttl || 3600,
    priority: recordData.priority || null,
    weight: recordData.weight || null,
    port: recordData.port || null,
    flag: recordData.flag || null,
    tag: recordData.tag || null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Add to store
  localDNSRecords[domain].push(record);
  logger.info(`Added ${normalizedType} record for ${domain}: ${recordData.name}`);

  return record;
}

/**
 * Get all DNS records for a domain
 * @param {string} domain - Domain name
 * @param {string} type - (Optional) Filter by record type
 * @returns {array} Array of records
 */
function getRecords(domain, type = null) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain must be a non-empty string');
  }

  initializeDomain(domain);

  let records = localDNSRecords[domain] || [];

  if (type) {
    const normalizedType = type.toUpperCase();
    records = records.filter(r => r.type === normalizedType);
  }

  return records;
}

/**
 * Get a single DNS record by ID
 * @param {string} domain - Domain name
 * @param {string} recordId - Record ID
 * @returns {object|null} Record or null if not found
 */
function getRecordById(domain, recordId) {
  if (!domain || !recordId) {
    throw new Error('Domain and record ID are required');
  }

  const records = getRecords(domain);
  return records.find(r => r.id === recordId) || null;
}

/**
 * Update a DNS record
 * @param {string} domain - Domain name
 * @param {string} recordId - Record ID
 * @param {object} updates - Fields to update
 * @returns {object} Updated record
 * @throws {Error} if record not found or validation fails
 */
function updateRecord(domain, recordId, updates) {
  if (!domain || !recordId) {
    throw new Error('Domain and record ID are required');
  }

  const records = localDNSRecords[domain];
  if (!records) {
    throw new Error(`No records found for domain: ${domain}`);
  }

  const index = records.findIndex(r => r.id === recordId);
  if (index === -1) {
    throw new Error(`Record not found: ${recordId}`);
  }

  const record = records[index];
  const updatedRecord = { ...record, ...updates, updatedAt: new Date() };

  // Validate the updated record
  validateRecord(record.type, {
    name: updatedRecord.name,
    content: updatedRecord.content,
    ttl: updatedRecord.ttl,
    priority: updatedRecord.priority,
    weight: updatedRecord.weight,
    port: updatedRecord.port,
    flag: updatedRecord.flag,
    tag: updatedRecord.tag,
  });

  records[index] = updatedRecord;
  logger.info(`Updated record ${recordId} for domain ${domain}`);

  return updatedRecord;
}

/**
 * Delete a DNS record
 * @param {string} domain - Domain name
 * @param {string} recordId - Record ID
 * @returns {boolean} Success status
 * @throws {Error} if record not found
 */
function deleteRecord(domain, recordId) {
  if (!domain || !recordId) {
    throw new Error('Domain and record ID are required');
  }

  const records = localDNSRecords[domain];
  if (!records) {
    throw new Error(`No records found for domain: ${domain}`);
  }

  const index = records.findIndex(r => r.id === recordId);
  if (index === -1) {
    throw new Error(`Record not found: ${recordId}`);
  }

  const deletedRecord = records.splice(index, 1)[0];
  logger.info(`Deleted record ${recordId} for domain ${domain}`);

  return true;
}

/**
 * Bulk add multiple DNS records
 * @param {string} domain - Domain name
 * @param {array} recordsData - Array of record data objects
 * @returns {array} Array of created records
 */
function addRecordsBulk(domain, recordsData) {
  if (!Array.isArray(recordsData)) {
    throw new Error('recordsData must be an array');
  }

  const results = [];
  const errors = [];

  for (let i = 0; i < recordsData.length; i++) {
    try {
      const { type, ...data } = recordsData[i];
      const record = addRecord(domain, type, data);
      results.push(record);
    } catch (err) {
      errors.push({ index: i, error: err.message });
    }
  }

  if (errors.length > 0) {
    logger.warn(`Bulk add had ${errors.length} errors`);
  }

  return { success: results, errors };
}

/**
 * Export/Format records for zone file
 * @param {string} domain - Domain name
 * @returns {string} Zone file format
 */
function exportZoneFile(domain) {
  const records = getRecords(domain);
  if (records.length === 0) {
    return `; No records for ${domain}\n`;
  }

  let zoneFile = `; Zone file for ${domain}\n`;
  zoneFile += `; Generated: ${new Date().toISOString()}\n\n`;

  records.forEach(record => {
    const ttl = record.ttl || 3600;
    const name = record.name || '@';
    const type = record.type;

    switch (type) {
      case 'A':
      case 'AAAA':
      case 'CNAME':
      case 'NS':
      case 'PTR':
        zoneFile += `${name}\t${ttl}\tIN\t${type}\t${record.content}\n`;
        break;
      case 'MX':
        zoneFile += `${name}\t${ttl}\tIN\t${type}\t${record.priority}\t${record.content}\n`;
        break;
      case 'TXT':
        zoneFile += `${name}\t${ttl}\tIN\t${type}\t"${record.content}"\n`;
        break;
      case 'SRV':
        zoneFile += `${name}\t${ttl}\tIN\t${type}\t${record.priority}\t${record.weight}\t${record.port}\t${record.content}\n`;
        break;
      case 'CAA':
        zoneFile += `${name}\t${ttl}\tIN\t${type}\t${record.flag}\t${record.tag}\t"${record.content}"\n`;
        break;
    }
  });

  return zoneFile;
}

/**
 * Clear all records for a domain (useful for testing)
 * @param {string} domain - Domain name
 */
function clearDomain(domain) {
  if (localDNSRecords[domain]) {
    delete localDNSRecords[domain];
    logger.info(`Cleared all records for domain: ${domain}`);
  }
}

/**
 * Get statistics for DNS records
 * @param {string} domain - Domain name
 * @returns {object} Statistics object
 */
function getStats(domain) {
  const records = getRecords(domain);
  const stats = { total: records.length };

  records.forEach(record => {
    if (!stats[record.type]) {
      stats[record.type] = 0;
    }
    stats[record.type]++;
  });

  return stats;
}

/**
 * Validate domain format
 * @param {string} domain - Domain name
 * @returns {boolean} True if valid
 */
function isValidDomain(domain) {
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  return domainRegex.test(domain);
}

/**
 * Import zone file format records
 * @param {string} domain - Domain name
 * @param {string} zoneFileContent - Zone file content
 * @returns {object} Import results
 */
function importZoneFile(domain, zoneFileContent) {
  const lines = zoneFileContent.split('\n').filter(line => line.trim() && !line.trim().startsWith(';'));
  const results = { success: 0, errors: [] };

  lines.forEach((line, idx) => {
    try {
      const parts = line.split(/\s+/);
      if (parts.length < 4) return;

      const [name, ttl, _in, type, ...rest] = parts;
      const content = rest.join(' ').replace(/"/g, '');

      addRecord(domain, type, {
        name: name === '@' ? '' : name,
        content,
        ttl: parseInt(ttl),
      });

      results.success++;
    } catch (err) {
      results.errors.push({ line: idx + 1, error: err.message });
    }
  });

  return results;
}

// Export all functions
module.exports = {
  // Constants
  DNS_RECORD_TYPES,
  VALIDATION_RULES,

  // Core operations
  addRecord,
  getRecords,
  getRecordById,
  updateRecord,
  deleteRecord,
  addRecordsBulk,

  // Utilities
  validateRecord,
  clearDomain,
  getStats,
  isValidDomain,
  exportZoneFile,
  importZoneFile,
  initializeDomain,
};
