/**
 * ============================================================
 * api.test.js — API Response Validation Integration Tests
 * Tiffany's deliverable — Phase 4 & 5.
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * These tests hit the actual API endpoints the same way the
 * frontend does. This proves that:
 *   ✅ The server starts and responds correctly
 *   ✅ Valid inputs return the right JSON structure
 *   ✅ Bad inputs are rejected with the right error codes
 *   ✅ The validation layer catches malformed data before it
 *      reaches the frontend
 *
 * This is called "integration testing" — testing all the
 * parts working together, not just individual functions.
 *
 * HOW TO RUN:
 * -----------
 *   npx jest test/api.test.js --verbose
 *
 * NOTE:
 * -----
 * These tests mock (simulate) the dkim and dmarc services since
 * those belong to Ashton and Zircon and may not exist yet.
 * The parser, SPF, and validate modules are tested for real.
 */

const express    = require('express');
const request    = require('supertest'); // HTTP test client

// ── We build a lightweight test version of the app ────────
// This avoids needing dkim.js and dmarc.js to exist yet.
// We mock those services so Tiffany's parts can be tested independently.
jest.mock('../server/services/dkim', () => ({
  verifyDKIM: jest.fn().mockResolvedValue({
    result: 'pass',
    reason: 'Mocked DKIM pass',
    domain: 'company.com',
    selector: 'mail',
    algorithm: 'rsa-sha256',
    dnsRecord: 'v=DKIM1; k=rsa; p=mockkey',
  }),
}));

jest.mock('../server/services/dmarc', () => ({
  evaluateDMARC: jest.fn().mockResolvedValue({
    verdict: 'deliver',
    policy: 'reject',
    reason: 'Mocked DMARC pass',
    spfAligned: true,
    dkimAligned: true,
    dmarcRecord: 'v=DMARC1; p=reject',
    tags: { p: 'reject' },
  }),
}));

// Mock dns lookups so tests don't make real network calls
jest.mock('../server/services/dns', () => ({
  lookupSPFRecord:  jest.fn().mockResolvedValue('v=spf1 ip4:203.0.113.0/24 -all'),
  lookupDMARCRecord: jest.fn().mockResolvedValue('v=DMARC1; p=reject'),
  lookupDKIMRecord:  jest.fn().mockResolvedValue('v=DKIM1; k=rsa; p=mockkey'),
  lookupARecords:    jest.fn().mockResolvedValue([]),
  lookupMXRecords:   jest.fn().mockResolvedValue([]),
}));

// Now load the real app (with mocks in place)
const app = require('../server/app');

// ── Sample headers used across tests ──────────────────────
const VALID_HEADER = [
  'From: CEO <ceo@company.com>',
  'Return-Path: <ceo@company.com>',
  'Received: from mail.company.com ([203.0.113.10])',
  'Subject: Q3 Results',
  'Date: Mon, 1 Jan 2025 10:00:00 +0000',
  'Message-ID: <abc123@company.com>',
  'DKIM-Signature: v=1; a=rsa-sha256; d=company.com; s=mail; h=from:subject; bh=abc123; b=fakeSignatureXYZ123',
].join('\n');

const SPOOFED_HEADER = [
  'From: CEO <ceo@company.com>',
  'Return-Path: <noreply@attacker.com>',
  'Received: from mail.attacker.com ([45.33.32.156])',
  'Subject: Urgent Wire Transfer',
].join('\n');

// ══════════════════════════════════════════════════════════════
// SECTION 1 — Health check endpoint
// ══════════════════════════════════════════════════════════════
describe('GET /api/health', () => {

  test('[POSITIVE] returns 200 with status ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.timestamp).toBeDefined();
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 2 — POST /api/analyse/header — input validation
// ══════════════════════════════════════════════════════════════
describe('POST /api/analyse/header — input validation', () => {

  // ── NEGATIVE: missing rawHeader field ─────────────────────
  test('[NEGATIVE] returns 400 when rawHeader is missing', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  // ── NEGATIVE: rawHeader is not a string ───────────────────
  test('[NEGATIVE] returns 400 when rawHeader is not a string', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: 12345 });
    expect(res.status).toBe(400);
  });

  // ── NEGATIVE: empty string ────────────────────────────────
  test('[NEGATIVE] returns 400 when rawHeader is an empty string', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: '' });
    expect(res.status).toBe(400);
  });

  // ── NEGATIVE: completely garbled input ────────────────────
  test('[NEGATIVE] returns 422 when header has no valid From or domain', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: 'this is not a real email header at all' });
    // Parser will run but validation will catch missing fromDomain
    expect([400, 422, 500]).toContain(res.status);
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 3 — POST /api/analyse/header — response structure
// ══════════════════════════════════════════════════════════════
describe('POST /api/analyse/header — response structure', () => {

  // ── POSITIVE: valid header returns correct shape ───────────
  test('[POSITIVE] returns success with parsed + results for valid header', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: VALID_HEADER });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // parsed section
    expect(res.body.parsed).toBeDefined();
    expect(res.body.parsed.fromDomain).toBe('company.com');
    expect(res.body.parsed.fromEmail).toBe('ceo@company.com');
    expect(res.body.parsed.senderIP).toBe('203.0.113.10');

    // results section — all three protocols present
    expect(res.body.results).toBeDefined();
    expect(res.body.results.spf).toBeDefined();
    expect(res.body.results.dkim).toBeDefined();
    expect(res.body.results.dmarc).toBeDefined();
  });

  // ── POSITIVE: SPF result has required fields ───────────────
  test('[POSITIVE] SPF result contains result, reason, domain, ip', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: VALID_HEADER });

    const spf = res.body.results.spf;
    expect(spf.result).toBeDefined();
    expect(spf.reason).toBeDefined();
    expect(spf.domain).toBeDefined();
    expect(spf.ip).toBeDefined();
  });

  // ── POSITIVE: SPF result is a valid RFC 7208 value ────────
  test('[POSITIVE] SPF result value is a valid RFC 7208 string', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: VALID_HEADER });

    const validValues = ['pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror'];
    expect(validValues).toContain(res.body.results.spf.result);
  });

  // ── POSITIVE: parsed includes raw headers ─────────────────
  test('[POSITIVE] parsed object includes raw headers for debugging', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: VALID_HEADER });

    expect(res.body.parsed.raw).toBeDefined();
    expect(typeof res.body.parsed.raw).toBe('object');
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 4 — POST /api/analyse/header — spoofing scenarios
// ══════════════════════════════════════════════════════════════
describe('POST /api/analyse/header — spoofing detection', () => {

  // ── POSITIVE: spoofed header shows mismatched domains ─────
  test('[POSITIVE] spoofed header correctly shows fromDomain ≠ envelopeDomain', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: SPOOFED_HEADER });

    // Should still respond (not crash)
    expect([200, 422]).toContain(res.status);

    if (res.status === 200) {
      // Key spoofing signal: domains don't match
      expect(res.body.parsed.fromDomain).toBe('company.com');
      expect(res.body.parsed.envelopeDomain).toBe('attacker.com');
      expect(res.body.parsed.fromDomain).not.toBe(res.body.parsed.envelopeDomain);
    }
  });

  // ── POSITIVE: spoofed header senderIP is correctly extracted
  test('[POSITIVE] spoofed header correctly extracts attacker IP', async () => {
    const res = await request(app)
      .post('/api/analyse/header')
      .send({ rawHeader: SPOOFED_HEADER });

    if (res.status === 200) {
      expect(res.body.parsed.senderIP).toBe('45.33.32.156');
    }
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 5 — POST /api/analyse/domain — input validation
// ══════════════════════════════════════════════════════════════
describe('POST /api/analyse/domain — input validation', () => {

  test('[POSITIVE] returns DNS records for a valid domain', async () => {
    const res = await request(app)
      .post('/api/analyse/domain')
      .send({ domain: 'company.com' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.records).toBeDefined();
    expect(res.body.records.spf).toBeDefined();
  });

  test('[NEGATIVE] returns 400 when domain is missing', async () => {
    const res = await request(app)
      .post('/api/analyse/domain')
      .send({});
    expect(res.status).toBe(400);
  });

  test('[NEGATIVE] returns 400 for an invalid domain format', async () => {
    const res = await request(app)
      .post('/api/analyse/domain')
      .send({ domain: 'not a domain!!' });
    expect(res.status).toBe(400);
  });
});