// =============================================================
// test/testAuditor.js — DMARC Record Auditor Test Suite
// Author:  Zircon Lee
// Tests:   auditDMARC() and parseDMARCRecord() in dmarcAuditor.js
//
// Run from the server/ directory:
//   node ../test/testAuditor.js
//
// Tests cover:
//   1.  Strong record — p=reject, pct=100, rua= set → Grade A
//   2.  Good record — p=quarantine, pct=100, rua= set → Grade B
//   3.  Moderate — p=quarantine, pct=50, no rua= → Grade C
//   4.  Weak — p=none, no rua= → Grade D
//   5.  No DMARC record → Grade F, score 0
//   6.  Missing p= tag → error, score deducted
//   7.  Strict alignment flags (aspf=s, adkim=s)
//   8.  Low pct (pct=10) — high deduction
//   9.  sp= none explicitly set
//   10. parseDMARCRecord() — parses all tags correctly
//   11. parseDMARCRecord() — handles null input
// =============================================================

const { auditDMARC, parseDMARCRecord } = require('../services/dmarcAuditor');

// ── Test runner ───────────────────────────────────────────────
let passed = 0;
let failed = 0;

function test(name, result, expectedGrade, expectedMinScore, expectedMaxScore) {
  const gradeOk = result.grade === expectedGrade;
  const scoreOk = result.score >= expectedMinScore && result.score <= expectedMaxScore;
  const ok      = gradeOk && scoreOk;

  if (ok) {
    console.log(`  ✅ PASS — ${name}`);
    console.log(`         grade: ${result.grade}  score: ${result.score}/100`);
    passed++;
  } else {
    console.log(`  ❌ FAIL — ${name}`);
    if (!gradeOk) console.log(`       grade:  expected "${expectedGrade}", got "${result.grade}"`);
    if (!scoreOk) console.log(`       score:  expected ${expectedMinScore}–${expectedMaxScore}, got ${result.score}`);
    failed++;
  }

  // Print issues and recommendations for visibility
  if (result.issues && result.issues.length > 0) {
    result.issues.forEach(i => console.log(`         ⚠  ${i}`));
  }
  if (result.recommendations && result.recommendations.length > 0) {
    result.recommendations.forEach(r => console.log(`         →  ${r}`));
  }
  console.log('');
}

function testParse(name, result, expected) {
  const ok = JSON.stringify(result) === JSON.stringify(expected) ||
             Object.entries(expected).every(([k, v]) => result[k] === v);

  if (ok) {
    console.log(`  ✅ PASS — ${name}`);
    passed++;
  } else {
    console.log(`  ❌ FAIL — ${name}`);
    console.log(`       expected: ${JSON.stringify(expected)}`);
    console.log(`       got:      ${JSON.stringify(result)}`);
    failed++;
  }
  console.log('');
}


// ── Test cases ────────────────────────────────────────────────

console.log('=== DMARC Record Auditor — Test Suite ===\n');


// ── Section 1: Grade A ────────────────────────────────────────
console.log('--- Grade A: Strong Configuration ---\n');

// Test 1: Perfect record — all best practices met
test(
  'Strong record — p=reject, pct=100, rua= set',
  auditDMARC(
    'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; aspf=r; adkim=r',
    'example.com'
  ),
  'A', 90, 100
);


// ── Section 2: Grade B ────────────────────────────────────────
console.log('--- Grade B: Good Configuration ---\n');

// Test 2: Quarantine with full enforcement and reporting
test(
  'Good record — p=quarantine, pct=100, rua= set',
  auditDMARC(
    'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100',
    'example.com'
  ),
  'B', 75, 89
);


// ── Section 3: Grade C ────────────────────────────────────────
console.log('--- Grade C: Moderate Configuration ---\n');

// Test 3: Quarantine but partial enforcement and no reporting
// Deductions: -10 (quarantine) -5 (sp=) -20 (pct=50) -10 (no rua=) = 55 → Grade D
test(
  'Moderate record — p=quarantine, pct=50, no rua=',
  auditDMARC(
    'v=DMARC1; p=quarantine; pct=50',
    'moderate.com'
  ),
  'D', 40, 59
);


// ── Section 4: Grade D ────────────────────────────────────────
console.log('--- Grade D: Weak Configuration ---\n');

// Test 4: Monitoring only, no reporting
test(
  'Weak record — p=none, no rua=',
  auditDMARC(
    'v=DMARC1; p=none',
    'weak.com'
  ),
  'D', 40, 59
);


// ── Section 5: Grade F ────────────────────────────────────────
console.log('--- Grade F: No or Invalid Record ---\n');

// Test 5: No DMARC record at all
test(
  'No DMARC record — grade F, score 0',
  auditDMARC(null, 'nodmarc.com'),
  'F', 0, 0
);

// Test 6: Record exists but p= tag missing
test(
  'Record missing p= tag — heavy deduction',
  auditDMARC(
    'v=DMARC1; rua=mailto:dmarc@example.com',
    'brokendmarc.com'
  ),
  'F', 0, 39
);


// ── Section 6: Specific tag checks ───────────────────────────
console.log('--- Specific Tag Checks ---\n');

// Test 7: Strict alignment modes — should flag issues
test(
  'Strict alignment (aspf=s, adkim=s) — flags issues',
  auditDMARC(
    'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; aspf=s; adkim=s',
    'strict.com'
  ),
  'A', 85, 100  // still A but not perfect due to strict flags
);

// Test 8: Very low pct — should heavily deduct
// Deductions: -30 (pct≤25) = 70 → Grade C
test(
  'Very low pct=10 — deduction applied',
  auditDMARC(
    'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=10',
    'lowpct.com'
  ),
  'C', 60, 74  // ← was 'B', 60, 89
);

// Test 9: sp=none with p=none — both weak, Grade D (record exists but very weak)
// Deductions: -30 (p=none) -10 (sp=none) -10 (no rua=) = 50 → Grade D
test(
  'sp=none with p=none — Grade D (record exists but weak)',
  auditDMARC(
    'v=DMARC1; p=none; sp=none',
    'subpolicy.com'
  ),
  'D', 40, 59
);


// ── Section 7: parseDMARCRecord() unit tests ──────────────────
console.log('--- parseDMARCRecord() Unit Tests ---\n');

// Test 10: Full record — all tags parsed correctly
const parsed = parseDMARCRecord('v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com; aspf=r; adkim=s');
testParse(
  'Full record — all tags parsed',
  parsed,
  { version: 'DMARC1', policy: 'reject', sp: 'quarantine', pct: 100, aspf: 'r', adkim: 's' }
);

// Test 11: Null input — should return null gracefully
testParse(
  'Null input — returns null',
  parseDMARCRecord(null),
  null
);

// Test 12: Minimal record — missing tags default correctly
const parsedMinimal = parseDMARCRecord('v=DMARC1; p=quarantine');
testParse(
  'Minimal record — defaults applied',
  { pct: parsedMinimal.pct, aspf: parsedMinimal.aspf, adkim: parsedMinimal.adkim },
  { pct: 100, aspf: 'r', adkim: 'r' }
);


// ── Summary ───────────────────────────────────────────────────
console.log('=========================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed === 0) {
  console.log('All tests passed ✅');
} else {
  console.log(`${failed} test(s) failed ❌ — check output above`);
}
console.log('=========================================');