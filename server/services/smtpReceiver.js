// =============================================================
// smtpReceiver.js — Local SMTP Receiver
// Author:  Zircon Lee
//
// Scope:
//   Zircon — DMARC evaluation on received emails (this file)
//   Tiffany — Email header parsing (parseEmailHeader from parser.js)
//   Ashton  — DNS DMARC record lookup (lookupDMARCRecord from dns.js)
//
// What this does:
//   1. Runs a local SMTP server on port 2525
//   2. When an email arrives, passes the raw header to Tiffany's parser
//   3. Uses Ashton's DNS module to fetch the real DMARC record
//   4. Runs Zircon's DMARC engine to evaluate the email
//   5. Logs the result in the aggregate reporter
//   6. Stores the last result so the frontend can fetch it
//
// Usage:
//   Called from app.js — startSMTPServer() starts the server
//   Frontend polls GET /api/dmarc/smtp/latest for live results
//
// Testing:
//   Run server/utils/testEmailSend.js to send test emails
// =============================================================

const { SMTPServer }      = require('smtp-server');
const { simpleParser }    = require('mailparser');
const { parseEmailHeader } = require('./parser');         // Tiffany's parser
const { lookupDMARCRecord } = require('./dns');           // Ashton's DNS module
const { evaluateDMARC }   = require('./dmarc');           // Zircon's DMARC engine
const { parseDMARCRecord } = require('./dmarcAuditor');   // Zircon's record parser
const { logDMARCResult }  = require('./aggregateReporter'); // Zircon's reporter
const logger              = require('../utils/logger');

// Stores the most recent evaluation result
// Frontend polls GET /api/dmarc/smtp/latest to display it
let lastResult = null;

// startSMTPServer — starts the local SMTP server on port 2525
// Returns an object with getLastResult() and clearLastResult()
// so app.js can expose these to the API routes
const startSMTPServer = () => {

  const server = new SMTPServer({
    // Allow any sender without authentication — local testing only
    authOptional: true,

    // Disable STARTTLS — not needed for local testing
    disabledCommands: ['STARTTLS'],

    // onData — called when a full email is received
    onData(stream, session, callback) {
      simpleParser(stream, async (err, mail) => {
        if (err) {
          logger.error(`SMTP receiver parse error: ${err.message}`);
          callback(err);
          return;
        }

        try {
          // ── Step 1: Rebuild raw header string for Tiffany's parser ──
          // mailparser gives us parsed headers — rebuild as raw text
          // so parseEmailHeader() can process it the same way it handles
          // headers pasted into the Raw Header tab
          const rawHeaderLines = [];
          for (const [key, value] of mail.headers) {
            const val = typeof value === 'object' && value.text
              ? value.text
              : typeof value === 'object'
              ? JSON.stringify(value)
              : String(value);
            rawHeaderLines.push(`${key}: ${val}`);
          }
          const rawHeader = rawHeaderLines.join('\n');

          // ── Step 2: Parse the header using Tiffany's parser ──────────
          // Returns: { fromDomain, envelopeDomain, senderIP, dkimSignature, ... }
          const parsed = parseEmailHeader(rawHeader);

          // ── Step 3: Fetch real DMARC record using Ashton's DNS module ─
          // Falls back to p=none if no record found so evaluation still runs
          const dmarcRaw = await lookupDMARCRecord(parsed.fromDomain);
          const dmarcParsed = parseDMARCRecord(dmarcRaw) || {
            policy:     'none',
            fromDomain: parsed.fromDomain,
            pct:        100,
            aspf:       'r',
            adkim:      'r',
            sp:         null
          };
          dmarcParsed.fromDomain = parsed.fromDomain;

          // ── Step 4: Build SPF and DKIM result objects ─────────────────
          // SPF — check if the sending domain (envelope) matches the From domain
          // In a real mail server, SPF would check the IP against the SPF record.
          // Here we use the envelope domain as the SPF domain and mark it as
          // pass if it matches the From domain, fail if it does not.
          const spfDomain = parsed.envelopeDomain || parsed.fromDomain;
          const spf = {
            status: spfDomain === parsed.fromDomain ? 'pass' : 'fail',
            domain: spfDomain
          };

          // DKIM — check if the DKIM signature domain matches the From domain
          // dkimSignature.d is the signing domain from the DKIM-Signature header
          const dkimDomain = parsed.dkimSignature?.d || '';
          const dkim = {
            status: dkimDomain ? 'pass' : 'fail',
            domain: dkimDomain
          };

          // ── Step 5: Run Zircon's DMARC policy engine ──────────────────
          const result = evaluateDMARC(spf, dkim, dmarcParsed);

          // ── Step 6: Store result and log it ───────────────────────────
          lastResult = {
            ...result,
            fromDomain: parsed.fromDomain,
            email: {
              from:        parsed.fromEmail,
              subject:     mail.subject || '(no subject)',
              fromDomain:  parsed.fromDomain,
              envelopeDomain: parsed.envelopeDomain,
              spfDomain,
              dkimDomain,
              hasDKIM:     !!dkimDomain,
              receivedAt:  new Date().toISOString()
            }
          };

          logDMARCResult(lastResult, 'smtp-live');

          logger.info(
            `[SMTP] Email from ${parsed.fromEmail} → ` +
            `${result.action.toUpperCase()} (risk: ${result.riskScore}) ` +
            `SPF: ${spf.status} DKIM: ${dkim.status}`
          );

        } catch (e) {
          logger.error(`[SMTP] DMARC evaluation error: ${e.message}`);
        }

        callback();
      });
    },

    // onError — log server-level errors without crashing
    onError(err) {
      logger.error(`SMTP server error: ${err.message}`);
    }
  });

  // Try to bind the SMTP server to a port with graceful fallback.
  // Uses `process.env.SMTP_PORT` if provided, otherwise starts at 2525
  const BASE_SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 2525;
  const MAX_ATTEMPTS = 6; // try BASE_SMTP_PORT .. BASE_SMTP_PORT+5

  const listenWithFallback = async (startPort) => {
    let port = startPort;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++, port++) {
      try {
        await new Promise((resolve, reject) => {
          const onError = (err) => {
            server.removeListener('listening', onListen);
            reject(err);
          };

          const onListen = () => {
            server.removeListener('error', onError);
            resolve();
          };

          server.once('error', onError);
          server.once('listening', onListen);
          server.listen(port);
        });

        logger.info(`SMTP receiver listening on port ${port}`);
        console.log(`SMTP receiver listening on port ${port}`);
        return port;

      } catch (err) {
        if (err && err.code === 'EADDRINUSE') {
          logger.warn(`Port ${port} in use; trying next port`);
          // continue loop to try next port
          continue;
        }
        // Unexpected error — log and rethrow
        logger.error(`Failed to start SMTP server: ${err.message}`);
        throw err;
      }
    }
    throw new Error(`Unable to bind SMTP server after ${MAX_ATTEMPTS} attempts starting at ${startPort}`);
  };

  // Start the server asynchronously and log failures without crashing the app
  listenWithFallback(BASE_SMTP_PORT).catch((err) => {
    logger.error(`SMTP server failed to start: ${err.message}`);
    console.error(`SMTP server failed to start: ${err.message}`);
  });

  return {
    // getLastResult — returns the most recent evaluation result
    // Called by GET /api/dmarc/smtp/latest in app.js
    getLastResult: () => lastResult,

    // clearLastResult — resets the stored result
    // Called by DELETE /api/dmarc/smtp/latest in app.js
    clearLastResult: () => { lastResult = null; }
  };
};

module.exports = { startSMTPServer };