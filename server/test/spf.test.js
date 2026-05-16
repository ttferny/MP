/**
 * ============================================================
 * spf.test.js — SPF/DKIM Positive & Negative Test Cases
 * Tiffany's deliverable — Phase 5.
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * These are automated tests that prove our code works correctly.
 * Each test gives a known input and checks we get the expected output.
 *
 * POSITIVE tests = scenarios that SHOULD pass ✅
 * NEGATIVE tests = scenarios that SHOULD fail ❌
 *
 * Running these tests gives us evidence for the project report
 * that all our scenarios were verified and the system behaves correctly.
 *
 * HOW TO RUN:
 * -----------
 *   npm install --save-dev jest
 *   npx jest test/spf.test.js --verbose
 *
 * MODULES TESTED:
 * ---------------
 *   parser.js  — parseEmailHeader(), splitHeaders(), extractEmail(), extractDomain()
 *   spf.js     — parseSPFRecord(), SPF_RESULTS
 *   validate.js— validateParsedHeader(), validateSPFResult(), isValidIP(), isValidDomain()
 */

// ── Import modules under test ──────────────────────────────
const { parseEmailHeader, splitHeaders, extractEmail, extractDomain } = require('../services/parser');
const { parseSPFRecord, SPF_RESULTS } = require('../services/spf');
const {
  validateParsedHeader,
  validateSPFResult,
  isValidIP,
  isValidDomain,
  isValidEmail,
} = require('../utils/validate');

// ══════════════════════════════════════════════════════════════
// SECTION 1 — parser.js unit tests
// ══════════════════════════════════════════════════════════════
describe('parser.js — splitHeaders()', () => {

  // ── POSITIVE: normal single-line headers ──────────────────
  test('[POSITIVE] parses basic key-value headers correctly', () => {
    const raw = 'From: test@example.com\nSubject: Hello\nDate: Mon, 1 Jan 2025 00:00:00 +0000';
    const result = splitHeaders(raw);
    expect(result['from']).toBe('test@example.com');
    expect(result['subject']).toBe('Hello');
    expect(result['date']).toBe('Mon, 1 Jan 2025 00:00:00 +0000');
  });

  // ── POSITIVE: folded headers (multi-line) ─────────────────
  test('[POSITIVE] unfolds folded header lines correctly', () => {
    const raw = 'Subject: This is a very\n long subject line';
    const result = splitHeaders(raw);
    expect(result['subject']).toBe('This is a very long subject line');
  });

  // ── POSITIVE: duplicate headers stored as array ───────────
  test('[POSITIVE] stores duplicate headers (Received) as an array', () => {
    const raw = 'Received: from server1.com\nReceived: from server2.com';
    const result = splitHeaders(raw);
    expect(Array.isArray(result['received'])).toBe(true);
    expect(result['received'].length).toBe(2);
  });

  // ── POSITIVE: keys are normalised to lowercase ────────────
  test('[POSITIVE] normalises header keys to lowercase', () => {
    const raw = 'FROM: test@example.com\nSUBJECT: Test';
    const result = splitHeaders(raw);
    expect(result['from']).toBeDefined();
    expect(result['subject']).toBeDefined();
  });

  // ── NEGATIVE: lines without colon are skipped ─────────────
  test('[NEGATIVE] skips lines with no colon separator', () => {
    const raw = 'This line has no colon\nFrom: test@example.com';
    const result = splitHeaders(raw);
    expect(Object.keys(result)).toHaveLength(1);
    expect(result['from']).toBe('test@example.com');
  });

  // ── NEGATIVE: empty string returns empty object ───────────
  test('[NEGATIVE] returns empty object for empty input', () => {
    const result = splitHeaders('');
    expect(Object.keys(result)).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────
describe('parser.js — extractEmail() and extractDomain()', () => {

  // ── POSITIVE: display name format ─────────────────────────
  test('[POSITIVE] extracts email from "Display Name <email>" format', () => {
    expect(extractEmail('John Smith <john@example.com>')).toBe('john@example.com');
  });

  // ── POSITIVE: plain email address ─────────────────────────
  test('[POSITIVE] returns plain email address as-is', () => {
    expect(extractEmail('john@example.com')).toBe('john@example.com');
  });

  // ── POSITIVE: extracts domain from email ──────────────────
  test('[POSITIVE] extracts domain from email address', () => {
    expect(extractDomain('ceo@company.com')).toBe('company.com');
  });

  // ── NEGATIVE: returns empty string for no @ symbol ────────
  test('[NEGATIVE] returns empty string if email has no @ symbol', () => {
    expect(extractDomain('notanemail')).toBe('');
  });

  // ── NEGATIVE: returns empty string for empty input ────────
  test('[NEGATIVE] returns empty string for empty input', () => {
    expect(extractEmail('')).toBe('');
    expect(extractDomain('')).toBe('');
  });
});

// ─────────────────────────────────────────────
describe('parser.js — parseEmailHeader()', () => {

  const validHeader = [
    'From: CEO <ceo@company.com>',
    'Return-Path: <ceo@company.com>',
    'Received: from mail.company.com ([203.0.113.10])',
    'Subject: Q3 Results',
    'Date: Mon, 1 Jan 2025 10:00:00 +0000',
    'Message-ID: <abc123@company.com>',
    'DKIM-Signature: v=1; a=rsa-sha256; d=company.com; s=mail; h=from:subject; bh=abc123; b=fakeSignature',
  ].join('\n');

  // ── POSITIVE: correctly extracts all key fields ───────────
  test('[POSITIVE] extracts fromDomain from From header', () => {
    const parsed = parseEmailHeader(validHeader);
    expect(parsed.fromDomain).toBe('company.com');
  });

  test('[POSITIVE] extracts fromEmail correctly', () => {
    const parsed = parseEmailHeader(validHeader);
    expect(parsed.fromEmail).toBe('ceo@company.com');
  });

  test('[POSITIVE] extracts envelopeDomain from Return-Path', () => {
    const parsed = parseEmailHeader(validHeader);
    expect(parsed.envelopeDomain).toBe('company.com');
  });

  test('[POSITIVE] extracts senderIP from Received header', () => {
    const parsed = parseEmailHeader(validHeader);
    expect(parsed.senderIP).toBe('203.0.113.10');
  });

  test('[POSITIVE] parses DKIM-Signature fields correctly', () => {
    const parsed = parseEmailHeader(validHeader);
    expect(parsed.dkimSignature.d).toBe('company.com');
    expect(parsed.dkimSignature.s).toBe('mail');
    expect(parsed.dkimSignature.a).toBe('rsa-sha256');
  });

  test('[POSITIVE] returns raw headers object', () => {
    const parsed = parseEmailHeader(validHeader);
    expect(parsed.raw).toBeDefined();
    expect(typeof parsed.raw).toBe('object');
  });

  // ── POSITIVE: spoofed header — From differs from Return-Path
  test('[POSITIVE] detects mismatched From and Return-Path domains (spoofing signal)', () => {
    const spoofedHeader = [
      'From: CEO <ceo@company.com>',
      'Return-Path: <noreply@attacker.com>',
      'Received: from mail.attacker.com ([45.33.32.156])',
      'Subject: Urgent Wire Transfer',
    ].join('\n');
    const parsed = parseEmailHeader(spoofedHeader);
    // fromDomain and envelopeDomain should differ — key signal for DMARC
    expect(parsed.fromDomain).toBe('company.com');
    expect(parsed.envelopeDomain).toBe('attacker.com');
    expect(parsed.fromDomain).not.toBe(parsed.envelopeDomain);
  });

  // ── POSITIVE: header with no DKIM signature ───────────────
  test('[POSITIVE] returns empty dkimSignature object when no DKIM header present', () => {
    const noDkimHeader = 'From: test@example.com\nSubject: No DKIM';
    const parsed = parseEmailHeader(noDkimHeader);
    expect(parsed.dkimSignature).toEqual({});
  });

  // ── POSITIVE: fallback — envelopeDomain uses fromDomain if no Return-Path ──
  test('[POSITIVE] falls back to fromDomain when Return-Path is absent', () => {
    const header = 'From: user@example.com\nSubject: No return path';
    const parsed = parseEmailHeader(header);
    expect(parsed.envelopeDomain).toBe('example.com');
  });

  // ── NEGATIVE: throws on empty input ───────────────────────
  test('[NEGATIVE] throws an error for empty input', () => {
    expect(() => parseEmailHeader('')).toThrow();
  });

  // ── NEGATIVE: throws on non-string input ──────────────────
  test('[NEGATIVE] throws an error for non-string input', () => {
    expect(() => parseEmailHeader(null)).toThrow();
    expect(() => parseEmailHeader(123)).toThrow();
  });

  // ── NEGATIVE: no senderIP when Received has no IP ─────────
  test('[NEGATIVE] returns empty senderIP when Received header has no IP bracket', () => {
    const header = 'From: test@example.com\nReceived: from mail.example.com by mx.host.com';
    const parsed = parseEmailHeader(header);
    expect(parsed.senderIP).toBe('');
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 2 — spf.js unit tests (parseSPFRecord + SPF_RESULTS)
// ══════════════════════════════════════════════════════════════
describe('spf.js — parseSPFRecord()', () => {

  // ── POSITIVE: basic record with ip4 and -all ──────────────
  test('[POSITIVE] parses a basic SPF record correctly', () => {
    const record = 'v=spf1 ip4:203.0.113.0/24 -all';
    const mechanisms = parseSPFRecord(record);
    expect(mechanisms).toHaveLength(2);
    expect(mechanisms[0].mechName).toBe('ip4');
    expect(mechanisms[0].mechValue).toBe('203.0.113.0/24');
    expect(mechanisms[0].qualifier).toBe('+'); // default qualifier
    expect(mechanisms[1].mechName).toBe('all');
    expect(mechanisms[1].qualifier).toBe('-'); // fail qualifier
  });

  // ── POSITIVE: include mechanism ───────────────────────────
  test('[POSITIVE] parses include mechanism correctly', () => {
    const record = 'v=spf1 include:_spf.google.com ~all';
    const mechanisms = parseSPFRecord(record);
    expect(mechanisms[0].mechName).toBe('include');
    expect(mechanisms[0].mechValue).toBe('_spf.google.com');
    expect(mechanisms[1].qualifier).toBe('~'); // softfail
  });

  // ── POSITIVE: multiple mechanisms ─────────────────────────
  test('[POSITIVE] parses multiple mechanisms in order', () => {
    const record = 'v=spf1 ip4:1.2.3.4 mx a include:sendgrid.net -all';
    const mechanisms = parseSPFRecord(record);
    expect(mechanisms.map(m => m.mechName)).toEqual(['ip4', 'mx', 'a', 'include', 'all']);
  });

  // ── POSITIVE: explicit + qualifier ────────────────────────
  test('[POSITIVE] correctly handles explicit + qualifier', () => {
    const record = 'v=spf1 +ip4:10.0.0.1 -all';
    const mechanisms = parseSPFRecord(record);
    expect(mechanisms[0].qualifier).toBe('+');
  });

  // ── POSITIVE: SPF_RESULTS constants are correct strings ───
  test('[POSITIVE] SPF_RESULTS constants match RFC 7208 values', () => {
    expect(SPF_RESULTS.PASS).toBe('pass');
    expect(SPF_RESULTS.FAIL).toBe('fail');
    expect(SPF_RESULTS.SOFTFAIL).toBe('softfail');
    expect(SPF_RESULTS.NEUTRAL).toBe('neutral');
    expect(SPF_RESULTS.NONE).toBe('none');
    expect(SPF_RESULTS.PERMERROR).toBe('permerror');
    expect(SPF_RESULTS.TEMPERROR).toBe('temperror');
  });

  // ── NEGATIVE: throws if no v=spf1 prefix ──────────────────
  test('[NEGATIVE] throws error if record does not start with v=spf1', () => {
    expect(() => parseSPFRecord('ip4:1.2.3.4 -all')).toThrow('Invalid SPF record');
  });

  // ── NEGATIVE: throws on empty string ──────────────────────
  test('[NEGATIVE] throws error for empty string input', () => {
    expect(() => parseSPFRecord('')).toThrow();
  });

  // ── NEGATIVE: throws for completely wrong format ───────────
  test('[NEGATIVE] throws for non-SPF TXT record content', () => {
    expect(() => parseSPFRecord('v=DMARC1; p=reject')).toThrow('Invalid SPF record');
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 3 — validate.js unit tests
// ══════════════════════════════════════════════════════════════
describe('validate.js — isValidIP()', () => {

  test('[POSITIVE] accepts valid IPv4 addresses', () => {
    expect(isValidIP('203.0.113.10')).toBe(true);
    expect(isValidIP('0.0.0.0')).toBe(true);
    expect(isValidIP('255.255.255.255')).toBe(true);
  });

  test('[NEGATIVE] rejects IP with out-of-range octet', () => {
    expect(isValidIP('256.0.0.1')).toBe(false);
  });

  test('[NEGATIVE] rejects non-IP strings', () => {
    expect(isValidIP('not-an-ip')).toBe(false);
    expect(isValidIP('')).toBe(false);
    expect(isValidIP(null)).toBe(false);
  });

  test('[NEGATIVE] rejects partial IP', () => {
    expect(isValidIP('192.168.1')).toBe(false);
  });
});

describe('validate.js — isValidDomain()', () => {

  test('[POSITIVE] accepts valid domains', () => {
    expect(isValidDomain('company.com')).toBe(true);
    expect(isValidDomain('mail.company.com')).toBe(true);
    expect(isValidDomain('example.co.uk')).toBe(true);
  });

  test('[NEGATIVE] rejects single-label domains (no dot)', () => {
    expect(isValidDomain('localhost')).toBe(false);
  });

  test('[NEGATIVE] rejects empty string', () => {
    expect(isValidDomain('')).toBe(false);
    expect(isValidDomain(null)).toBe(false);
  });

  test('[NEGATIVE] rejects domain with invalid characters', () => {
    expect(isValidDomain('bad domain!.com')).toBe(false);
  });
});

describe('validate.js — validateParsedHeader()', () => {

  const goodParsed = {
    from: 'CEO <ceo@company.com>',
    fromEmail: 'ceo@company.com',
    fromDomain: 'company.com',
    envelopeFrom: 'ceo@company.com',
    envelopeDomain: 'company.com',
    senderIP: '203.0.113.10',
    dkimSignature: {},
    receivedChain: [],
    raw: {},
  };

  test('[POSITIVE] validates a complete parsed header object', () => {
    const result = validateParsedHeader(goodParsed);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  test('[NEGATIVE] fails when fromDomain is missing', () => {
    const bad = { ...goodParsed, fromDomain: '' };
    const result = validateParsedHeader(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('fromDomain'))).toBe(true);
  });

  test('[NEGATIVE] fails when fromEmail is not a valid email', () => {
    const bad = { ...goodParsed, fromEmail: 'notanemail' };
    const result = validateParsedHeader(bad);
    expect(result.valid).toBe(false);
  });

  test('[NEGATIVE] fails when envelopeDomain is missing', () => {
    const bad = { ...goodParsed, envelopeDomain: '' };
    const result = validateParsedHeader(bad);
    expect(result.valid).toBe(false);
  });

  test('[NEGATIVE] fails when dkimSignature is not an object', () => {
    const bad = { ...goodParsed, dkimSignature: 'invalid' };
    const result = validateParsedHeader(bad);
    expect(result.valid).toBe(false);
  });

  test('[NEGATIVE] fails when input is not an object', () => {
    const result = validateParsedHeader(null);
    expect(result.valid).toBe(false);
  });
});

describe('validate.js — validateSPFResult()', () => {

  const goodSPF = {
    result: 'pass',
    reason: 'Matched mechanism: ip4:203.0.113.0/24',
    domain: 'company.com',
    ip: '203.0.113.10',
  };

  test('[POSITIVE] validates a correct SPF result object', () => {
    const r = validateSPFResult(goodSPF);
    expect(r.valid).toBe(true);
  });

  test('[POSITIVE] accepts all valid RFC 7208 result values', () => {
    const valid = ['pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror'];
    valid.forEach(result => {
      const r = validateSPFResult({ ...goodSPF, result });
      expect(r.valid).toBe(true);
    });
  });

  test('[NEGATIVE] fails when result value is not a valid SPF result', () => {
    const r = validateSPFResult({ ...goodSPF, result: 'unknown' });
    expect(r.valid).toBe(false);
  });

  test('[NEGATIVE] fails when reason is missing', () => {
    const r = validateSPFResult({ ...goodSPF, reason: '' });
    expect(r.valid).toBe(false);
  });

  test('[NEGATIVE] fails when domain is missing', () => {
    const r = validateSPFResult({ ...goodSPF, domain: '' });
    expect(r.valid).toBe(false);
  });

  test('[NEGATIVE] fails when input is null', () => {
    const r = validateSPFResult(null);
    expect(r.valid).toBe(false);
  });
});