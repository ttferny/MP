// =============================================================
// utils/testEmailSend.js — Test Email Sender
// Author:  Zircon Lee
//
// Sends test emails to the local SMTP receiver on port 2525.
// Used to verify that smtpReceiver.js correctly evaluates
// different email scenarios through the DMARC engine.
//
// Run from the server/ directory:
//   node utils/testEmailSend.js
//
// Make sure node app.js is running first.
// =============================================================

const nodemailer = require('nodemailer');

// Connect to the local SMTP receiver on port 2525
const transporter = nodemailer.createTransport({
  host:   'localhost',
  port:   2525,
  secure: false,
  tls:    { rejectUnauthorized: false }
});

// sendEmail — sends a single test email with custom headers
async function sendEmail(from, subject, authResults, returnPath) {
  await transporter.sendMail({
    from,
    to:      'test@localhost',
    subject,
    text:    `Test email: ${subject}`,
    headers: {
      'Authentication-Results': authResults,
      'Return-Path':            `<${returnPath}>`
    }
  });
  console.log(`Sent: ${subject}`);
}

// Run all test scenarios
(async () => {
  console.log('Sending test emails to SMTP receiver on port 2525...\n');

  // Test 1 — Legitimate email
  // SPF and DKIM both pass and align with the From domain
  await sendEmail(
    'noreply@google.com',
    'Test 1: Legitimate Email',
    'spf=pass smtp.mailfrom=google.com; dkim=pass header.d=google.com',
    'noreply@google.com'
  );

  // Test 2 — Spoofed email (basic spoof)
  // From says dbs.com.sg but actually sent from evil.com
  await sendEmail(
    'security@dbs.com.sg',
    'Test 2: Spoofed Sender',
    'spf=fail smtp.mailfrom=evil.com; dkim=fail',
    'bounce@evil.com'
  );

  // Test 3 — CEO fraud
  // SPF passes on lookalike domain, no DKIM signature
  await sendEmail(
    'ceo@company.com',
    'Test 3: CEO Fraud',
    'spf=pass smtp.mailfrom=ceo-company.com; dkim=none',
    'ceo@ceo-company.com'
  );

  // Test 4 — SPF misaligned
  // SPF passes but on the wrong domain — the key DMARC scenario
  await sendEmail(
    'support@legitbank.com',
    'Test 4: SPF Pass but Misaligned',
    'spf=pass smtp.mailfrom=evil.com; dkim=fail',
    'bounce@evil.com'
  );

  console.log('\nAll test emails sent.');
  console.log('Check GET http://localhost:3000/api/dmarc/smtp/latest for the last result.');
  console.log('Check the Reports tab on the website to see all logged results.');
})();