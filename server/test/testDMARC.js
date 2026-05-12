// =============================================================
// test/testDMARC.js — DMARC Policy Engine Test Suite
// Author:  Zircon Lee
// Tests:   evaluateDMARC() and checkAlignment() in dmarc.js
//
// Run from the server/ directory:
//   node ../test/testDMARC.js
//
// Tests cover:
//   1.  Legitimate email — SPF aligned
//   2.  Legitimate email — DKIM aligned
//   3.  Both SPF and DKIM aligned
//   4.  Spoof — both fail, p=reject
//   5.  Spoof — both fail, p=quarantine
//   6.  Spoof — both fail, p=none (monitor only)
//   7.  SPF pass but misaligned domain (key DMARC scenario)
//   8.  Strict alignment — subdomain fails aspf=s
//   9.  Relaxed alignment — subdomain passes aspf=r
//   10. Subdomain policy (sp=) override
//   11. Partial enforcement pct=50
//   12. Missing SPF input — error handling
//   13. Missing DMARC record — error handling
//   14. CEO fraud — lookalike domain
// =============================================================

const { evaluateDMARC, checkAlignment } = require('../services/dmarc');

// ── Test runner ───────────────────────────────────────────────
let passed = 0;
let failed = 0;

function test(name, result, expectedStatus, expectedAction) {
  const statusOk = result.status === expectedStatus;
  const actionOk = result.action === expectedAction;
  const ok       = statusOk && actionOk;

  if (ok) {
    console.log(`  ✅ PASS — ${name}`);
    passed++;
  } else {
    console.log(`  ❌ FAIL — ${name}`);
    if (!statusOk) console.log(`       status:  expected "${expectedStatus}", got "${result.status}"`);
    if (!actionOk) console.log(`       action:  expected "${expectedAction}", got "${result.action}"`);
    failed++;
  }

  // Always print reason and risk score for visibility
  console.log(`         reason: ${result.reason}`);
  if (result.riskScore !== undefined) {
    console.log(`         risk:   ${result.riskScore}/100`);
  }
  console.log('');
}


// ── Test cases ────────────────────────────────────────────────

console.log('=== DMARC Policy Engine — Test Suite ===\n');


// ── Section 1: Passing scenarios ─────────────────────────────
console.log('--- Legitimate Email Scenarios ---\n');

// Test 1: SPF aligned — From and SPF domain match
test(
  'Legitimate email — SPF aligned',
  evaluateDMARC(
    { status: "pass", domain: "legitbank.com" },
    { status: "fail", domain: "" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "pass", "deliver"
);

// Test 2: DKIM aligned — From and DKIM domain match
test(
  'Legitimate email — DKIM aligned',
  evaluateDMARC(
    { status: "fail", domain: "" },
    { status: "pass", domain: "legitbank.com" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "pass", "deliver"
);

// Test 3: Both SPF and DKIM aligned — maximum legitimacy
test(
  'Legitimate email — both SPF and DKIM aligned',
  evaluateDMARC(
    { status: "pass", domain: "legitbank.com" },
    { status: "pass", domain: "legitbank.com" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "pass", "deliver"
);


// ── Section 2: Policy enforcement scenarios ───────────────────
console.log('--- Policy Enforcement Scenarios ---\n');

// Test 4: Spoofed email, p=reject — should be blocked
test(
  'Spoofed email — p=reject → blocked',
  evaluateDMARC(
    { status: "fail", domain: "evil.com" },
    { status: "fail", domain: "evil.com" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "fail", "reject"
);

// Test 5: Spoofed email, p=quarantine — should go to spam
test(
  'Spoofed email — p=quarantine → spam',
  evaluateDMARC(
    { status: "fail", domain: "evil.com" },
    { status: "fail", domain: "evil.com" },
    { policy: "quarantine", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "fail", "quarantine"
);

// Test 6: Spoofed email, p=none — detected but delivered (monitoring only)
test(
  'Spoofed email — p=none → delivered (monitor only)',
  evaluateDMARC(
    { status: "fail", domain: "evil.com" },
    { status: "fail", domain: "evil.com" },
    { policy: "none", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "fail", "deliver"
);


// ── Section 3: Alignment scenarios ───────────────────────────
console.log('--- Alignment Scenarios ---\n');

// Test 7: SPF passes on evil.com but From: is legitbank.com
// This is the most important DMARC scenario — SPF alone is not enough
test(
  'SPF pass but misaligned domain — DMARC catches it',
  evaluateDMARC(
    { status: "pass", domain: "evil.com" },
    { status: "fail", domain: "" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "fail", "reject"
);

// Test 8: Subdomain fails strict SPF alignment (aspf=s)
// mail.legitbank.com !== legitbank.com in strict mode
test(
  'Subdomain — fails strict alignment (aspf=s)',
  evaluateDMARC(
    { status: "pass", domain: "mail.legitbank.com" },
    { status: "fail", domain: "" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "s", adkim: "r" }
  ),
  "fail", "reject"
);

// Test 9: Same subdomain passes relaxed alignment (aspf=r)
// mail.legitbank.com ends with .legitbank.com → relaxed match
test(
  'Subdomain — passes relaxed alignment (aspf=r)',
  evaluateDMARC(
    { status: "pass", domain: "mail.legitbank.com" },
    { status: "fail", domain: "" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "pass", "deliver"
);


// ── Section 4: Advanced DMARC tag scenarios ───────────────────
console.log('--- Advanced Tag Scenarios ---\n');

// Test 10: sp= subdomain policy overrides main p=
// Auth domain (evil.com) is NOT a subdomain of fromDomain (mail.legitbank.com)
// so sp= does not apply — main p=reject is used.
// sp= only applies when the auth domain IS a subdomain of fromDomain.
// e.g. auth=sub.company.com, from=company.com → sp= applies
test(
  'Subdomain policy (sp=) — only applies when auth domain is subdomain of fromDomain',
  evaluateDMARC(
    { status: "fail", domain: "sub.company.com" },
    { status: "fail", domain: "sub.company.com" },
    { policy: "reject", sp: "none", fromDomain: "company.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "fail", "deliver"
);

// Test 11: pct=50 — policy only applies to 50% of emails
// The engine still returns the action — pct is informational in the result
test(
  'Partial enforcement pct=50 — action still returned',
  evaluateDMARC(
    { status: "fail", domain: "evil.com" },
    { status: "fail", domain: "evil.com" },
    { policy: "quarantine", fromDomain: "legitbank.com", pct: 50, aspf: "r", adkim: "r" }
  ),
  "fail", "quarantine"
);


// ── Section 5: Error handling ─────────────────────────────────
console.log('--- Error Handling ---\n');

// Test 12: Missing SPF input — should return error, not crash
test(
  'Missing SPF input — graceful error',
  evaluateDMARC(
    null,
    { status: "pass", domain: "legitbank.com" },
    { policy: "reject", fromDomain: "legitbank.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "error", "none"
);

// Test 13: Missing DMARC record — should return error, not crash
test(
  'Missing DMARC record — graceful error',
  evaluateDMARC(
    { status: "pass", domain: "legitbank.com" },
    { status: "pass", domain: "legitbank.com" },
    null
  ),
  "error", "none"
);


// ── Section 6: Real attack scenarios ─────────────────────────
console.log('--- Real Attack Scenarios ---\n');

// Test 14: CEO fraud — attacker registers ceo-company.com
// SPF passes on the lookalike domain, but fails DMARC alignment
test(
  'CEO fraud — SPF on lookalike domain fails alignment',
  evaluateDMARC(
    { status: "pass", domain: "ceo-company.com" },
    { status: "fail", domain: "" },
    { policy: "quarantine", fromDomain: "company.com", pct: 100, aspf: "r", adkim: "r" }
  ),
  "fail", "quarantine"
);


// ── Section 7: checkAlignment unit tests ─────────────────────
console.log('--- checkAlignment() Unit Tests ---\n');

function testAlignment(name, result, expected) {
  const ok = result === expected;
  if (ok) {
    console.log(`  ✅ PASS — ${name}`);
    passed++;
  } else {
    console.log(`  ❌ FAIL — ${name}`);
    console.log(`       expected: ${expected}, got: ${result}`);
    failed++;
  }
  console.log('');
}

// Exact match — strict and relaxed both pass
testAlignment('Exact domain match — relaxed', checkAlignment("pass", "legitbank.com", "legitbank.com", "r"), true);
testAlignment('Exact domain match — strict',  checkAlignment("pass", "legitbank.com", "legitbank.com", "s"), true);

// Subdomain — relaxed passes, strict fails
testAlignment('Subdomain — relaxed (should pass)', checkAlignment("pass", "mail.legitbank.com", "legitbank.com", "r"), true);
testAlignment('Subdomain — strict (should fail)',  checkAlignment("pass", "mail.legitbank.com", "legitbank.com", "s"), false);

// SPF fails — alignment should always be false regardless of domain
testAlignment('SPF fail — alignment always false', checkAlignment("fail", "legitbank.com", "legitbank.com", "r"), false);

// Wrong domain — should not align
testAlignment('Wrong domain — should not align', checkAlignment("pass", "evil.com", "legitbank.com", "r"), false);


// ── Summary ───────────────────────────────────────────────────
console.log('=========================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed === 0) {
  console.log('All tests passed ✅');
} else {
  console.log(`${failed} test(s) failed ❌ — check output above`);
}
console.log('=========================================');