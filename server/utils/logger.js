/**
 * ============================================================
 * logger.js — Simple Console Logger
 * ============================================================
 *
 * WHAT THIS FILE DOES:
 * --------------------
 * Every service (parser, SPF, DKIM, DMARC) calls logger.info(),
 * logger.warn(), or logger.error() to print messages to the terminal.
 * This helps us trace exactly what the server is doing step by step
 * during a demo — useful for pitching and debugging.
 *
 * Example output:
 *   [2025-08-01T10:00:00.000Z] [INFO]  Parsing email headers...
 *   [2025-08-01T10:00:00.010Z] [INFO]  SPF check — domain: company.com, IP: 203.0.113.5
 *   [2025-08-01T10:00:00.050Z] [INFO]  SPF result: pass (matched 'ip4:203.0.113.0/24')
 *   [2025-08-01T10:00:00.060Z] [WARN]  DKIM: no signature found in headers
 *   [2025-08-01T10:00:00.070Z] [INFO]  DMARC verdict: reject
 *
 * HOW IT LINKS:
 * -------------
 *   Imported by: parser.js, spf.js, dkim.js, dmarc.js, dns.js, app.js
 *   Does not import anything — it is a standalone utility.
 */

const LEVELS = { info: 'INFO', warn: 'WARN', error: 'ERROR' };

function log(level, msg) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${LEVELS[level] || 'LOG'}]  ${msg}`);
}

module.exports = {
  info:  (msg) => log('info',  msg),
  warn:  (msg) => log('warn',  msg),
  error: (msg) => log('error', msg),
};