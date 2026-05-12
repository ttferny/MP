/**
 * ============================================================
 * parser.js — Email Header Parser
 * Tiffany's deliverable.
 * ============================================================
 *
 * WHAT IS AN EMAIL HEADER? (simple version for pitching)
 * -------------------------------------------------------
 * Every email has two parts: the body (what you read) and the header
 * (invisible metadata — like a postal envelope with addresses, stamps,
 * and routing info).
 *
 * The header contains things like:
 *   From: boss@company.com
 *   Return-Path: <noreply@sender.com>
 *   Received: from mail.sender.com (203.0.113.5) ...
 *   DKIM-Signature: v=1; a=rsa-sha256; d=company.com; ...
 *
 * This file reads those raw lines and extracts the key values
 * needed by SPF, DKIM, and DMARC to do their checks.
 *
 * HOW THIS FILE LINKS TO THE REST OF THE PROJECT:
 * ------------------------------------------------
 *   routes/analyse.js calls parseEmailHeader(rawHeader)
 *         ↓
 *   parser.js returns a clean "parsed" object
 *         ↓
 *   spf.js   uses: parsed.senderIP, parsed.envelopeDomain
 *   dkim.js  uses: parsed.dkimSignature, parsed.fromDomain
 *   dmarc.js uses: parsed.fromDomain (to find DMARC policy)
 */

const logger = require('../utils/logger');

// ─────────────────────────────────────────────
// HELPER: splitHeaders
//
// Splits a raw header block into a key-value object.
// Handles "folded" headers (RFC 5322) — long headers can be split
// across multiple lines with a leading space/tab on continuation lines.
//
// Example folded header:
//   Subject: This is a very
//     long subject line
// → becomes → { subject: "This is a very long subject line" }
// ─────────────────────────────────────────────
function splitHeaders(raw) {
  // Unfold: join continuation lines (CRLF or LF + whitespace → single space)
  const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
  const lines = unfolded.split(/\r?\n/);
  const headers = {};

  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue; // skip lines without a colon

    const key = line.slice(0, idx).trim().toLowerCase(); // normalise key to lowercase
    const val = line.slice(idx + 1).trim();

    // Some headers can appear multiple times (e.g. "Received")
    // Store duplicates as an array
    if (headers[key]) {
      headers[key] = Array.isArray(headers[key])
        ? [...headers[key], val]
        : [headers[key], val];
    } else {
      headers[key] = val;
    }
  }
  return headers;
}

// ─────────────────────────────────────────────
// HELPER: extractEmail
//
// Pulls the email address out of a "Display Name <email>" string.
// e.g. "John Smith <john@example.com>" → "john@example.com"
// ─────────────────────────────────────────────
function extractEmail(str = '') {
  const match = str.match(/<([^>]+)>/);
  return match ? match[1].trim() : str.trim();
}

// ─────────────────────────────────────────────
// HELPER: extractDomain
//
// Gets the domain part from an email address.
// e.g. "john@example.com" → "example.com"
// ─────────────────────────────────────────────
function extractDomain(email = '') {
  const parts = email.split('@');
  return parts.length === 2 ? parts[1].toLowerCase() : '';
}

// ─────────────────────────────────────────────
// HELPER: parseDKIMSignature
//
// The DKIM-Signature header is a semicolon-separated list of key=value pairs.
// e.g. "v=1; a=rsa-sha256; d=example.com; s=selector1; b=ABC123..."
// → { v: "1", a: "rsa-sha256", d: "example.com", s: "selector1", b: "ABC123..." }
//
// Ashton's dkim.js will use these values to verify the signature.
// ─────────────────────────────────────────────
function parseDKIMSignature(sigHeader = '') {
  const result = {};
  const pairs = sigHeader.split(';');
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const k = pair.slice(0, eq).trim();
    const v = pair.slice(eq + 1).trim();
    result[k] = v;
  }
  return result;
}

// ─────────────────────────────────────────────
// MAIN EXPORT: parseEmailHeader
//
// Takes the raw email header text and returns a clean structured object.
// This object is the input to ALL downstream services (SPF, DKIM, DMARC).
//
// KEY VALUES EXTRACTED:
//   fromDomain      → used by DMARC (the visible "From" domain)
//   envelopeDomain  → used by SPF  (the actual sending domain, from Return-Path)
//   senderIP        → used by SPF  (extracted from the Received chain)
//   dkimSignature   → used by DKIM (the cryptographic signature to verify)
// ─────────────────────────────────────────────
function parseEmailHeader(rawHeader) {
  if (!rawHeader || typeof rawHeader !== 'string') {
    throw new Error('parseEmailHeader: rawHeader must be a non-empty string.');
  }

  const headers = splitHeaders(rawHeader);
  logger.info('Parsing email headers...');

  // ── From header ───────────────────────────────────────────
  // The visible sender the recipient sees in their email client.
  // Spoofed emails often have a fake "From" — DMARC checks this.
  const from = headers['from'] || '';
  const fromEmail = extractEmail(from);
  const fromDomain = extractDomain(fromEmail);
  // Example: "From: Fake Bank <security@realbank.com>" → fromDomain = "realbank.com"

  // ── Return-Path / Envelope From ───────────────────────────
  // The actual domain used during SMTP delivery (MAIL FROM command).
  // This is what SPF checks — it may differ from the From header in spoofed emails.
  const returnPath = Array.isArray(headers['return-path'])
    ? headers['return-path'][0]
    : (headers['return-path'] || '');
  const envelopeFrom = extractEmail(returnPath);
  const envelopeDomain = extractDomain(envelopeFrom) || fromDomain;
  // Example: "Return-Path: <bounce@attacker.com>" → envelopeDomain = "attacker.com"

  // ── Received headers (the routing chain) ──────────────────
  // Every mail server that handled this email adds a "Received" line.
  // The chain goes from the original sender (last item) to the final
  // recipient's server (first item).
  const receivedChain = Array.isArray(headers['received'])
    ? headers['received']
    : headers['received'] ? [headers['received']] : [];

  // Extract the originating IP from the last "Received" header
  // (the server that originally sent the email)
  // Typical format: "from mail.example.com ([203.0.113.5])"
  const senderIP = (() => {
    if (!receivedChain.length) return '';
    const last = receivedChain[receivedChain.length - 1];
    const ipMatch = last.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
    return ipMatch ? ipMatch[1] : '';
  })();
  // This IP is what SPF will check against the domain's authorised server list.

  // ── DKIM-Signature ────────────────────────────────────────
  // The cryptographic signature added by the sending mail server.
  // Ashton's dkim.js will use "d" (domain) and "s" (selector) to fetch
  // the public key from DNS and verify the signature.
  const dkimRaw = headers['dkim-signature'] || '';
  const dkimSignature = parseDKIMSignature(
    Array.isArray(dkimRaw) ? dkimRaw[0] : dkimRaw
  );

  // ── Assemble final parsed object ──────────────────────────
  const parsed = {
    // Identity fields
    from,                  // Full From header string
    fromEmail,             // e.g. "ceo@company.com"
    fromDomain,            // e.g. "company.com"       → used by DMARC
    envelopeFrom,          // e.g. "bounce@sender.com"
    envelopeDomain,        // e.g. "sender.com"        → used by SPF

    // Routing fields
    receivedChain,         // Array of all Received headers
    senderIP,              // Originating IP address   → used by SPF

    // Other common headers
    replyTo:   headers['reply-to']  || '',
    subject:   headers['subject']   || '',
    date:      headers['date']      || '',
    messageId: headers['message-id'] || '',

    // Authentication data
    dkimSignature,         // Parsed DKIM-Signature fields → used by DKIM
    authResultsRaw: headers['authentication-results'] || '', // Raw auth results if present

    // Full raw headers (available for debugging or display in the UI)
    raw: headers,
  };

  logger.info(`Header parsed — fromDomain: ${fromDomain}, envelopeDomain: ${envelopeDomain}, senderIP: ${senderIP}`);
  return parsed;
}

// Export the main function + helpers (helpers are exported for unit testing)
module.exports = { parseEmailHeader, extractEmail, extractDomain, splitHeaders };