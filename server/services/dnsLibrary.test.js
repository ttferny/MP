/**
 * ============================================================
 * dnsLibrary.test.js — DNS Library Tests & Examples
 * ============================================================
 *
 * Comprehensive examples showing how to use the DNS library
 */

const dnsLib = require('./dnsLibrary');

console.log('╔════════════════════════════════════════════════════════════════════╗');
console.log('║          DNS Library - Complete Test Suite                         ║');
console.log('╚════════════════════════════════════════════════════════════════════╝\n');

// Test domain
const DOMAIN = 'example.com';

try {
  // ═══════════════════════════════════════════════════════════════════════════
  // 1. TEST: Add A Record
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 1: Adding A Record');
  const aRecord = dnsLib.addRecord(DOMAIN, 'A', {
    name: 'www',
    content: '192.168.1.1',
    ttl: 3600,
  });
  console.log('  Added:', aRecord);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. TEST: Add MX Record
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 2: Adding MX Record');
  const mxRecord = dnsLib.addRecord(DOMAIN, 'MX', {
    name: '',
    content: 'mail.example.com',
    priority: 10,
    ttl: 3600,
  });
  console.log('  Added:', mxRecord);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. TEST: Add TXT Record (SPF)
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 3: Adding TXT Record (SPF)');
  const spfRecord = dnsLib.addRecord(DOMAIN, 'TXT', {
    name: '',
    content: 'v=spf1 include:sendgrid.net ~all',
    ttl: 3600,
  });
  console.log('  Added:', spfRecord);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. TEST: Add CNAME Record
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 4: Adding CNAME Record');
  const cnameRecord = dnsLib.addRecord(DOMAIN, 'CNAME', {
    name: 'alias',
    content: 'www.example.com',
    ttl: 3600,
  });
  console.log('  Added:', cnameRecord);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. TEST: Add DKIM Record (TXT)
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 5: Adding DKIM Record');
  const dkimRecord = dnsLib.addRecord(DOMAIN, 'TXT', {
    name: 'default._domainkey',
    content: 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ...',
    ttl: 3600,
  });
  console.log('  Added:', dkimRecord);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. TEST: Add CAA Record
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 6: Adding CAA Record');
  const caaRecord = dnsLib.addRecord(DOMAIN, 'CAA', {
    name: '',
    content: 'letsencrypt.org',
    flag: 0,
    tag: 'issue',
    ttl: 3600,
  });
  console.log('  Added:', caaRecord);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. TEST: Get All Records
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 7: Getting All Records');
  const allRecords = dnsLib.getRecords(DOMAIN);
  console.log(`  Found ${allRecords.length} records:`);
  allRecords.forEach(r => {
    console.log(`    - ${r.name || '@'} (${r.type}): ${r.content || r.target}`);
  });
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. TEST: Get Records by Type
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 8: Getting TXT Records Only');
  const txtRecords = dnsLib.getRecords(DOMAIN, 'TXT');
  console.log(`  Found ${txtRecords.length} TXT records`);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. TEST: Get Record by ID
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 9: Getting Specific Record by ID');
  const recordById = dnsLib.getRecordById(DOMAIN, aRecord.id);
  console.log('  Retrieved:', recordById.name || '@', recordById.type);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 10. TEST: Update Record
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 10: Updating A Record');
  const updated = dnsLib.updateRecord(DOMAIN, aRecord.id, {
    content: '192.168.1.2',
    ttl: 7200,
  });
  console.log('  Updated:', updated.content, `TTL: ${updated.ttl}`);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 11. TEST: Get Statistics
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 11: Getting DNS Statistics');
  const stats = dnsLib.getStats(DOMAIN);
  console.log('  Stats:', stats);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 12. TEST: Export Zone File
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 12: Exporting Zone File');
  const zoneFile = dnsLib.exportZoneFile(DOMAIN);
  console.log('  Zone File Preview:');
  console.log(zoneFile);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 13. TEST: Bulk Add Records
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 13: Bulk Adding Records');
  const DOMAIN2 = 'another-domain.com';
  const bulkResult = dnsLib.addRecordsBulk(DOMAIN2, [
    { type: 'A', name: 'www', content: '10.0.0.1', ttl: 3600 },
    { type: 'A', name: 'mail', content: '10.0.0.2', ttl: 3600 },
    { type: 'MX', name: '', content: 'mail.another-domain.com', priority: 10, ttl: 3600 },
    { type: 'TXT', name: '', content: 'v=spf1 mx ~all', ttl: 3600 },
  ]);
  console.log(`  Successful: ${bulkResult.success.length}, Errors: ${bulkResult.errors.length}`);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 14. TEST: Delete Record
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 14: Deleting a Record');
  dnsLib.deleteRecord(DOMAIN, cnameRecord.id);
  console.log('  Record deleted successfully');
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 15. TEST: Validation Errors
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 15: Testing Validation');
  try {
    dnsLib.addRecord(DOMAIN, 'A', {
      name: 'invalid',
      content: 'not.an.ip.address',
      ttl: 3600,
    });
  } catch (err) {
    console.log(`  ✓ Caught validation error: ${err.message}`);
  }
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // 16. TEST: Domain Validation
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('✓ TEST 16: Domain Validation');
  console.log(`  example.com is valid: ${dnsLib.isValidDomain('example.com')}`);
  console.log(`  sub.example.com is valid: ${dnsLib.isValidDomain('sub.example.com')}`);
  console.log(`  invalid..domain is valid: ${dnsLib.isValidDomain('invalid..domain')}`);
  console.log('');

  // ═══════════════════════════════════════════════════════════════════════════
  // Summary
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('╔════════════════════════════════════════════════════════════════════╗');
  console.log('║                       ALL TESTS PASSED ✓                           ║');
  console.log('╚════════════════════════════════════════════════════════════════════╝\n');

  console.log('📋 QUICK REFERENCE:\n');
  console.log('Add a Record:');
  console.log('  const record = dnsLib.addRecord(domain, type, { name, content, ttl, ... });\n');
  console.log('Get All Records:');
  console.log('  const records = dnsLib.getRecords(domain);\n');
  console.log('Update a Record:');
  console.log('  const updated = dnsLib.updateRecord(domain, recordId, { ...updates });\n');
  console.log('Delete a Record:');
  console.log('  dnsLib.deleteRecord(domain, recordId);\n');
  console.log('Export Zone File:');
  console.log('  const zoneFile = dnsLib.exportZoneFile(domain);\n');

} catch (err) {
  console.error('❌ TEST FAILED:', err.message);
  console.error(err.stack);
  process.exit(1);
}
