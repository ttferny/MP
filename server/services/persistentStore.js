const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

const STORAGE_DIR = path.join(__dirname, '..', 'data');
const DNS_STORE_FILE = path.join(STORAGE_DIR, 'dns-library.json');
const AUDIT_FILE = path.join(STORAGE_DIR, 'automation-audit.json');

function ensureStorageDir() {
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }
}

function loadJsonFile(filePath, fallback = {}) {
  ensureStorageDir();
  if (!fs.existsSync(filePath)) {
    return fallback;
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return raw ? JSON.parse(raw) : fallback;
  } catch (err) {
    logger.warn(`Unable to read ${filePath}: ${err.message}`);
    return fallback;
  }
}

function saveJsonFile(filePath, data) {
  ensureStorageDir();
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function loadDnsStore() {
  const data = loadJsonFile(DNS_STORE_FILE, {});
  return data.records || {};
}

function saveDnsStore(recordsByDomain) {
  saveJsonFile(DNS_STORE_FILE, { records: recordsByDomain });
}

function loadAuditLog() {
  const data = loadJsonFile(AUDIT_FILE, []);
  return Array.isArray(data) ? data : [];
}

function appendAuditEntry(entry) {
  const auditLog = loadAuditLog();
  auditLog.push({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    ...entry,
  });
  saveJsonFile(AUDIT_FILE, auditLog);
  return auditLog[auditLog.length - 1];
}

function clearPersistedState() {
  if (fs.existsSync(DNS_STORE_FILE)) {
    fs.rmSync(DNS_STORE_FILE, { force: true });
  }
  if (fs.existsSync(AUDIT_FILE)) {
    fs.rmSync(AUDIT_FILE, { force: true });
  }
}

module.exports = {
  loadDnsStore,
  saveDnsStore,
  loadAuditLog,
  appendAuditEntry,
  clearPersistedState,
};
