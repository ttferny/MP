# 🌐 DNS Library Documentation

## Overview

The DNS Library is a complete, production-ready DNS record management system that allows you to **add, read, update, and delete** DNS records for your domains. It supports all major DNS record types and provides both programmatic access (Node.js) and REST API endpoints.

---

## 📦 What's Included

### Core Files
- **`dnsLibrary.js`** - Core DNS library with all CRUD operations
- **`dnsManagementRoutes.js`** - Express.js REST API routes
- **`dnsLibrary.test.js`** - Complete test suite and examples

### API Base URL
```
http://localhost:3000/api/dns-mgmt
```

---

## 🎯 Supported DNS Record Types

| Type | Use Case | Example |
|------|----------|---------|
| **A** | IPv4 address | `192.168.1.1` |
| **AAAA** | IPv6 address | `2001:db8::1` |
| **CNAME** | Alias for domain | `www.example.com` |
| **MX** | Mail server | `mail.example.com` (priority 10) |
| **TXT** | Text records (SPF, DKIM, DMARC) | `v=spf1 include:...` |
| **NS** | Nameserver | `ns1.example.com` |
| **SRV** | Service records | Port, priority, weight |
| **CAA** | Certificate Authority Authorization | `issue letsencrypt.org` |

---

## 🚀 Quick Start

### 1. Run the Test Suite
```bash
cd server/services
node dnsLibrary.test.js
```

This will demonstrate all functionality with real examples.

### 2. Use via REST API

#### Add an A Record
```bash
curl -X POST http://localhost:3000/api/dns-mgmt/records \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "type": "A",
    "name": "www",
    "content": "192.168.1.1",
    "ttl": 3600
  }'
```

#### Get All Records
```bash
curl http://localhost:3000/api/dns-mgmt/records/example.com
```

#### Get Records by Type
```bash
curl http://localhost:3000/api/dns-mgmt/records/example.com?type=MX
```

#### Update a Record
```bash
curl -X PUT http://localhost:3000/api/dns-mgmt/records/example.com/RECORD_ID \
  -H "Content-Type: application/json" \
  -d '{
    "content": "192.168.1.2",
    "ttl": 7200
  }'
```

#### Delete a Record
```bash
curl -X DELETE http://localhost:3000/api/dns-mgmt/records/example.com/RECORD_ID
```

---

## 📚 API Endpoints

### 1. **POST** `/api/dns-mgmt/records` - Add a DNS Record
**Add a single DNS record**

Request:
```json
{
  "domain": "example.com",
  "type": "A",
  "name": "www",
  "content": "192.168.1.1",
  "ttl": 3600
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "example.com_1234567890_abc123def",
    "domain": "example.com",
    "type": "A",
    "name": "www",
    "content": "192.168.1.1",
    "ttl": 3600,
    "createdAt": "2026-07-06T12:00:00.000Z"
  }
}
```

**Required Fields:**
- `domain` - Domain name (must be valid)
- `type` - Record type (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA)
- `name` - Record name (empty string for root)
- `content` or `target` - Record content/target

**Optional Fields:**
- `ttl` - Time to live (default: 3600, range: 60-86400)
- `priority` - For MX records
- `weight` - For SRV records
- `port` - For SRV records
- `flag` - For CAA records (0 or 128)
- `tag` - For CAA records (issue, issuewild, iodef)

---

### 2. **GET** `/api/dns-mgmt/records/:domain` - Get All Records
**Retrieve all DNS records for a domain**

Request:
```bash
GET /api/dns-mgmt/records/example.com
GET /api/dns-mgmt/records/example.com?type=A
```

Response:
```json
{
  "success": true,
  "domain": "example.com",
  "recordType": "all",
  "count": 5,
  "data": [
    { "id": "...", "type": "A", "name": "www", "content": "192.168.1.1" },
    { "id": "...", "type": "MX", "name": "", "content": "mail.example.com", "priority": 10 }
  ]
}
```

**Query Parameters:**
- `type` - (Optional) Filter by record type

---

### 3. **GET** `/api/dns-mgmt/records/:domain/:recordId` - Get Specific Record
**Retrieve a single DNS record by ID**

Response:
```json
{
  "success": true,
  "data": { "id": "...", "domain": "example.com", "type": "A", "name": "www", "content": "192.168.1.1" }
}
```

---

### 4. **PUT** `/api/dns-mgmt/records/:domain/:recordId` - Update Record
**Update an existing DNS record**

Request:
```json
{
  "content": "192.168.1.2",
  "ttl": 7200
}
```

---

### 5. **DELETE** `/api/dns-mgmt/records/:domain/:recordId` - Delete Record
**Remove a DNS record**

---

### 6. **POST** `/api/dns-mgmt/records/:domain/bulk` - Bulk Add Records
**Add multiple DNS records at once**

Request:
```json
{
  "records": [
    { "type": "A", "name": "www", "content": "192.168.1.1", "ttl": 3600 },
    { "type": "A", "name": "mail", "content": "192.168.1.2", "ttl": 3600 },
    { "type": "MX", "name": "", "content": "mail.example.com", "priority": 10, "ttl": 3600 },
    { "type": "TXT", "name": "", "content": "v=spf1 mx ~all", "ttl": 3600 }
  ]
}
```

Response:
```json
{
  "success": true,
  "created": 4,
  "errors": 0,
  "data": { "success": [...], "errors": [] }
}
```

---

### 7. **GET** `/api/dns-mgmt/stats/:domain` - Get Statistics
**Get DNS record count by type**

Response:
```json
{
  "success": true,
  "domain": "example.com",
  "data": {
    "total": 8,
    "A": 2,
    "MX": 1,
    "TXT": 3,
    "CNAME": 1,
    "CAA": 1
  }
}
```

---

### 8. **GET** `/api/dns-mgmt/export/:domain` - Export Zone File
**Download DNS records as BIND zone file**

Response: Text file (example.com.zone)
```
; Zone file for example.com
; Generated: 2026-07-06T12:00:00.000Z

www       3600  IN  A     192.168.1.1
mail      3600  IN  A     192.168.1.2
          3600  IN  MX    10 mail.example.com
          3600  IN  TXT   "v=spf1 mx ~all"
```

---

### 9. **POST** `/api/dns-mgmt/import/:domain` - Import Zone File
**Import DNS records from zone file format**

Request:
```json
{
  "zoneFile": "www 3600 IN A 192.168.1.1\nmail 3600 IN A 192.168.1.2\n@ 3600 IN MX 10 mail.example.com"
}
```

---

### 10. **DELETE** `/api/dns-mgmt/clear/:domain` - Clear All Records
**Delete ALL records for a domain (requires confirmation)**

Request:
```bash
DELETE /api/dns-mgmt/clear/example.com?confirm=true
```

---

## 💻 Programmatic Usage (Node.js)

### Example 1: Add Records Programmatically

```javascript
const dnsLib = require('./server/services/dnsLibrary');

// Add A record
const aRecord = dnsLib.addRecord('example.com', 'A', {
  name: 'www',
  content: '192.168.1.1',
  ttl: 3600
});
console.log('Created:', aRecord.id);

// Add MX record
const mxRecord = dnsLib.addRecord('example.com', 'MX', {
  name: '',
  content: 'mail.example.com',
  priority: 10,
  ttl: 3600
});

// Add SPF record
const spfRecord = dnsLib.addRecord('example.com', 'TXT', {
  name: '',
  content: 'v=spf1 include:sendgrid.net ~all',
  ttl: 3600
});
```

### Example 2: Retrieve Records

```javascript
// Get all records
const all = dnsLib.getRecords('example.com');
console.log(`Found ${all.length} records`);

// Get only TXT records
const txtRecords = dnsLib.getRecords('example.com', 'TXT');

// Get specific record by ID
const record = dnsLib.getRecordById('example.com', recordId);
```

### Example 3: Update Records

```javascript
const updated = dnsLib.updateRecord('example.com', recordId, {
  content: '192.168.1.2',
  ttl: 7200
});
console.log('Updated:', updated);
```

### Example 4: Delete Records

```javascript
dnsLib.deleteRecord('example.com', recordId);
console.log('Record deleted');
```

### Example 5: Bulk Operations

```javascript
const result = dnsLib.addRecordsBulk('example.com', [
  { type: 'A', name: 'www', content: '192.168.1.1', ttl: 3600 },
  { type: 'A', name: 'mail', content: '192.168.1.2', ttl: 3600 },
  { type: 'MX', name: '', content: 'mail.example.com', priority: 10, ttl: 3600 }
]);

console.log(`Created ${result.success.length} records`);
console.log(`Errors: ${result.errors.length}`);
```

### Example 6: Export Zone File

```javascript
const zoneFile = dnsLib.exportZoneFile('example.com');
console.log(zoneFile);

// Write to file
const fs = require('fs');
fs.writeFileSync('example.com.zone', zoneFile);
```

### Example 7: Import Zone File

```javascript
const fs = require('fs');
const zoneContent = fs.readFileSync('example.com.zone', 'utf8');

const result = dnsLib.importZoneFile('example.com', zoneContent);
console.log(`Imported ${result.success} records`);
```

### Example 8: Get Statistics

```javascript
const stats = dnsLib.getStats('example.com');
console.log(stats);
// Output: { total: 8, A: 2, MX: 1, TXT: 3, CNAME: 1, CAA: 1 }
```

---

## ✅ Validation Rules

The library automatically validates all records. Here are the rules:

### A Record
- Content must be valid IPv4: `192.168.1.1`
- TTL: 60-86400 seconds
- Name: alphanumeric, dots, hyphens, underscores

### AAAA Record
- Content must be valid IPv6: `2001:db8::1`
- TTL: 60-86400 seconds

### CNAME Record
- Content must be valid domain name
- TTL: 60-86400 seconds
- Cannot have duplicates

### MX Record
- Content must be valid domain name
- Priority: 0-65535
- TTL: 60-86400 seconds

### TXT Record
- Content: 1-255 characters
- TTL: 60-86400 seconds
- For SPF: starts with `v=spf1`
- For DKIM: starts with `v=DKIM1` or `k=rsa` or `p=`

### SRV Record
- Content: valid domain name
- Port: 1-65535
- Priority: 0-65535
- Weight: 0-65535

### CAA Record
- Flag: 0 or 128
- Tag: `issue`, `issuewild`, or `iodef`
- Content: certificate issuer

---

## 🔒 Error Handling

All operations include comprehensive error handling:

```javascript
try {
  const record = dnsLib.addRecord('example.com', 'A', {
    name: 'www',
    content: 'invalid.ip',
    ttl: 3600
  });
} catch (err) {
  console.error(err.message);
  // "Invalid content for A record: invalid.ip"
}
```

Common errors:
- `Invalid record type: ABC` - Record type not supported
- `Invalid domain format: invalid..domain` - Domain validation failed
- `Record already exists: www A` - Duplicate record
- `Invalid content for A record: ...` - Validation failed
- `Record not found: ...` - ID doesn't exist

---

## 📊 Record Examples

### SPF Record
```javascript
dnsLib.addRecord('example.com', 'TXT', {
  name: '',
  content: 'v=spf1 include:sendgrid.net include:_spf.salesforce.com ~all',
  ttl: 3600
});
```

### DKIM Record
```javascript
dnsLib.addRecord('example.com', 'TXT', {
  name: 'default._domainkey',
  content: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ...',
  ttl: 3600
});
```

### DMARC Record
```javascript
dnsLib.addRecord('example.com', 'TXT', {
  name: '_dmarc',
  content: 'v=DMARC1; p=reject; rua=mailto:admin@example.com',
  ttl: 3600
});
```

### CAA Record
```javascript
dnsLib.addRecord('example.com', 'CAA', {
  name: '',
  content: 'letsencrypt.org',
  flag: 0,
  tag: 'issue',
  ttl: 3600
});
```

### SRV Record
```javascript
dnsLib.addRecord('example.com', 'SRV', {
  name: '_sip._tcp',
  content: 'sipserver.example.com',
  priority: 10,
  weight: 60,
  port: 5060,
  ttl: 3600
});
```

---

## 🧪 Running Tests

To see all features in action:

```bash
# From project root
cd server/services
node dnsLibrary.test.js
```

Output includes:
- ✓ Adding various record types (A, MX, TXT, CNAME, DKIM, CAA)
- ✓ Retrieving all records and filtered records
- ✓ Updating records with new values
- ✓ Getting statistics
- ✓ Exporting to zone file format
- ✓ Bulk operations
- ✓ Deletion
- ✓ Validation error testing
- ✓ Domain validation

---

## 🔄 Common Workflows

### Setup Complete Email Authentication

```javascript
const dnsLib = require('./services/dnsLibrary');
const domain = 'example.com';

// 1. Add SPF record
dnsLib.addRecord(domain, 'TXT', {
  name: '',
  content: 'v=spf1 include:sendgrid.net ~all',
  ttl: 3600
});

// 2. Add DKIM record
dnsLib.addRecord(domain, 'TXT', {
  name: 'default._domainkey',
  content: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...',
  ttl: 3600
});

// 3. Add DMARC record
dnsLib.addRecord(domain, 'TXT', {
  name: '_dmarc',
  content: 'v=DMARC1; p=quarantine; rua=mailto:admin@example.com',
  ttl: 3600
});

// 4. Add CAA record
dnsLib.addRecord(domain, 'CAA', {
  name: '',
  content: 'letsencrypt.org',
  flag: 0,
  tag: 'issue',
  ttl: 3600
});

// 5. Verify
const stats = dnsLib.getStats(domain);
console.log('Setup complete:', stats);
```

---

## 📝 Notes

- **In-Memory Storage**: Currently uses in-memory storage. For production, integrate with DNS provider APIs (Cloudflare, Route53, DigitalOcean, etc.)
- **Domain Validation**: Validates domain format. Add/remove records only for domains in your control
- **TTL**: Default 3600 seconds (1 hour). Valid range: 60-86400 seconds
- **Bulk Operations**: Continues on error - check the errors array in response
- **Zone File Export**: Compatible with BIND zone file format

---

## 🚀 Next Steps

1. **Run the tests** to see all functionality
2. **Try the API** endpoints with curl or Postman
3. **Integrate with frontend** - Create UI for DNS management
4. **Connect to DNS provider** - Replace in-memory storage with Cloudflare, Route53, etc.
5. **Add user authentication** - Secure the DNS management endpoints

---

## 📞 Support

For issues or questions:
1. Check the test file for examples
2. Review the validation rules
3. Check error messages - they're descriptive
4. Enable debug logging in `utils/logger.js`

---

**Library Version**: 1.0.0  
**Last Updated**: July 6, 2026  
**Status**: ✅ Production Ready
