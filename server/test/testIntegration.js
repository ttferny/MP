// test/testIntegration.js
// Tests all 13 scenarios end-to-end through the actual server API
// Server must be running on localhost:3000 before running this file
//
// Run from the server/ directory:
//   node test/testIntegration.js

const http = require('http');

let passed = 0;
let failed = 0;

// Sends a POST request to /api/dmarc/scenarios/:key
function callScenario(key, policy) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ policy, aspf: 'r', adkim: 'r' });
    const req = http.request({
      hostname: 'localhost', port: 3000,
      path: `/api/dmarc/scenarios/${key}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function test(name, result, expectedStatus, expectedAction) {
  const ok = result.status === expectedStatus && result.action === expectedAction;
  if (ok) {
    console.log(`  ✅ PASS — ${name}`);
    passed++;
  } else {
    console.log(`  ❌ FAIL — ${name}`);
    console.log(`       status:  expected "${expectedStatus}", got "${result.status}"`);
    console.log(`       action:  expected "${expectedAction}", got "${result.action}"`);
    failed++;
  }
  console.log(`         action: ${result.action}  risk: ${result.riskScore}`);
  console.log('');
}

async function runTests() {
  console.log('=== Integration Test — All 13 Scenarios via API ===\n');
  console.log('Make sure node app.js is running before this test.\n');

  const scenarios = [
    ['legitimate',       'reject',     'pass', 'deliver'],
    ['basic-spoof',      'reject',     'fail', 'reject'],
    ['ceo-fraud',        'quarantine', 'fail', 'quarantine'],
    ['banking-phish',    'reject',     'fail', 'reject'],
    ['monitor-only',     'none',       'fail', 'deliver'],
    ['spf-misalign',     'reject',     'fail', 'reject'],
    ['strict-fail',      'reject',     'pass', 'deliver'],
    ['relaxed-pass',     'reject',     'pass', 'deliver'],
    ['forwarded-email',  'reject',     'fail', 'reject'],
    ['subdomain-spoof',  'reject',     'pass', 'deliver'],
    ['pct-50-pass',      'quarantine', 'pass', 'deliver'],
    ['pct-50-fail',      'quarantine', 'fail', 'quarantine'],
    ['subdomain-policy', 'reject',     'fail', 'reject'],
  ];

  for (const [key, policy, expectedStatus, expectedAction] of scenarios) {
    try {
      const result = await callScenario(key, policy);
      test(key, result, expectedStatus, expectedAction);
    } catch (err) {
      console.log(`  ❌ ERROR — ${key}: ${err.message}\n`);
      failed++;
    }
  }

  console.log('=========================================');
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('All integration tests passed ✅');
  } else {
    console.log(`${failed} test(s) failed ❌`);
  }
  console.log('=========================================');
}

runTests();