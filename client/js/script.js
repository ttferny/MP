/**
 * script.js — Frontend Logic (Tiffany)
 * Connected to /api/analyse/header for header parsing and authentication evaluation.
 * AI phishing analysis card added — powered by Claude via aiChecker.js
 */

// ── DOM refs ───────────────────────────────────────────────
const analyseBtn    = document.getElementById('analyse-btn');
const clearBtn      = document.getElementById('clear-btn');
const inputError    = document.getElementById('input-error');
const emailFileInput = document.getElementById('email-file-input');
const uploadStatus = document.getElementById('upload-status');
const parsedFields  = document.getElementById('parsed-fields');
const spoofWarning  = document.getElementById('spoof-warning');

const spfSection    = document.getElementById('spf-section');
const spfPanel      = document.getElementById('spf-panel');
const spfBadge      = document.getElementById('spf-badge');
const spfSummary    = document.getElementById('spf-summary');
const spfDetails    = document.getElementById('spf-details');

const dkimSection   = document.getElementById('dkim-section');
const dkimPanel     = document.getElementById('dkim-panel');
const dkimBadge     = document.getElementById('dkim-badge');
const dkimSummary   = document.getElementById('dkim-summary');
const dkimDetails   = document.getElementById('dkim-details');

const dmarcSection  = document.getElementById('dmarc-section');
const dmarcPanel    = document.getElementById('dmarc-panel');
const dmarcBadge    = document.getElementById('dmarc-badge');
const dmarcSummary  = document.getElementById('dmarc-summary');
const dmarcDetails  = document.getElementById('dmarc-details');

// validation UI removed: no DOM refs

const accordionTriggers = document.querySelectorAll('.accordion-trigger');

accordionTriggers.forEach(trigger => {
  const panelId = trigger.dataset.target;
  const panel = document.getElementById(panelId);
  const item  = trigger.closest('.accordion-item');

  trigger.addEventListener('click', () => {
    const open = !panel.classList.contains('hidden');
    document.querySelectorAll('.accordion-item').forEach(el => {
      el.classList.remove('open');
      const inner = el.querySelector('.accordion-panel');
      if (inner) inner.classList.add('hidden');
    });

    if (!open) {
      panel.classList.remove('hidden');
      item.classList.add('open');
    }
  });
});

const testcaseContainer = document.getElementById('testcase-container');
const testcaseNote      = document.getElementById('testcase-note');

// AI refs — new
const aiSection = document.getElementById('ai-section');
const aiBadge   = document.getElementById('ai-badge');
const aiBody    = document.getElementById('ai-body');

// ══════════════════════════════════════════════════════════
// TEST CASES
// ══════════════════════════════════════════════════════════
const testCases = [
  {
    key: 'spf-pass',
    label: 'Authorized Sender',
    note: 'Example for a legitimate sender. Results depend on live DNS.',
    header: [
      'Delivered-To: tiffanyctj@gmail.com',
      'Received: by 2002:a05:6000:44c7:b0:45a:88d3:1f8e with SMTP id es7csp1464104wrb; Wed, 13 May 2026 21:43:37 -0700 (PDT)',
      'X-Received: by 2002:a05:6214:4291:b0:8b5:6654:7556 with SMTP id 6a1803df08f44-8c7bc05c18dmr105887276d6.42.1778733817499; Wed, 13 May 2026 21:43:37 -0700 (PDT)',
      'ARC-Seal: i=1; a=rsa-sha256; t=1778733817; cv=none; d=google.com; s=arc-20240605; b=ZrRt9ShdxvcYdEO4QtaRyWEveowad6RH5ggDJRXNMOxGgKuhnOuFh0QI2IAfdSEb0W eYVzZ+uk2jAnAMmNu7348ANGQdYA+L65VWgPHyrnfoq8fJomrP+1ciNrti13vfOqB1iY 17Z8fVC2pSboQx9YbD7vy+K+/MDlrUJTsrACsClwHQ+OVCszUJDjFu6SaW6agP0u7QOO 5DQ9eFgX1WCTzjN9Xe7wGhaqgvL/i6Z7+hXMzC2KMUa4mL03zdNnsUbycOwLeRozWcfU 8JzIwaudDED3UYh7h7ClYNf41EBAL8hPLyRxbCq3TFYaG4tnke3a1PzhmS+vYPA6T1Oq i+iA==',
      'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605; h=to:list-unsubscribe-post:list-unsubscribe:feedback-id:subject :message-id:mime-version:from:date:dkim-signature:dkim-signature; bh=CZ/lXL12g8zFOdRtMxiju5x5zNilpdfkfPR7eV4ioRk=; fh=UAu3lHCrD3qs5S/wTsFph9mwsMzTIYQ4pUFk6M/yGnY=; b=MKSnsrsEDmI7PGyWuBXqZL9sGCXRRZrKE8QLBQKud2FmyviMXctoNDmCzKoLMnTbHg Y023GRIH/4UDM3Kz33drgAQG7a4Mdr1CtPf3QqKm2fGMt76eBF3v//3FtWC9FbHP0FaG OeuTMh28iNV0OgzewjUTbA9CUIjZ1GnLG479yFNz26oYreQxVKsIgEii+7in3tSflH9W l/DsswjzcqwcEApEKqwE4dTPK2/qH02cxKPGhsjgrPGfqLhl76kYnc3WFv0JdIdRt3fU 7zUNOYeHi03E8s2TKkfgqiBu855Q120mQ9M5s81acI0+feG12H1+Fd2q4mGilBB50Uc9 yaZw==; dara=google.com',
      'ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@spotify.com header.s=s1 header.b=dpbpHWfc; dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=uLZ7Ui+l; spf=pass (google.com: domain of bounces+54769-04dc-tiffanyctj=gmail.com@em.spotify.com designates 159.183.83.220 as permitted sender) smtp.mailfrom="bounces+54769-04dc-tiffanyctj=gmail.com@em.spotify.com"; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=spotify.com',
      'Return-Path: <bounces+54769-04dc-tiffanyctj=gmail.com@em.spotify.com>',
      'Received: from o49.ptr2244.spotify.com (o49.ptr2244.spotify.com. [159.183.83.220]) by mx.google.com with ESMTPS id 6a1803df08f44-8c90d8e33f3si21265666d6.659.2026.05.13.21.43.36 for <tiffanyctj@gmail.com> (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128); Wed, 13 May 2026 21:43:37 -0700 (PDT)',
      'Received-SPF: pass (google.com: domain of bounces+54769-04dc-tiffanyctj=gmail.com@em.spotify.com designates 159.183.83.220 as permitted sender) client-ip=159.183.83.220;',
      'Authentication-Results: mx.google.com; dkim=pass header.i=@spotify.com header.s=s1 header.b=dpbpHWfc; dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=uLZ7Ui+l; spf=pass (google.com: domain of bounces+54769-04dc-tiffanyctj=gmail.com@em.spotify.com designates 159.183.83.220 as permitted sender) smtp.mailfrom="bounces+54769-04dc-tiffanyctj=gmail.com@em.spotify.com"; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=spotify.com',
      'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=spotify.com; h=content-type:date:from:mime-version:subject:feedback-id: list-unsubscribe:list-unsubscribe-post:to:cc:content-type:date:feedback-id:from: subject:to; s=s1; t=1778733815; bh=CZ/lXL12g8zFOdRtMxiju5x5zNilpdfkfPR7eV4ioRk=; b=dpbpHWfc5pgScOm5XstsQ9/+NVMIIOeHVNAuIClqV2C5fylCVsoeNzJ33T99DlYei53V hWeY6QW2jGkuqyxaFbf7qjQvfDAxfvODeoMkG+SPhyhvR7cfBFCkr60JfHTnZCuegt8Kn9 9hho8cuBuW2U1sV+KOu2FwiiuvYqqdYfzglGDltL+q4m9Uha+zEL4eX+EiNZ0E9aqr2mNU +qSi2dePrMshLMEfYF0p8ZHlqFChB50jBoeMBbizdUIyz2j3ZHLF0RTsWyWBGzMDW7RQjj ZvRcyYEQo1ihe4kBqCRST1MiEVayYKzruxbQ4HXa6iT2QC9BJmTs9TxuhPLF6qsg==',
      'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendgrid.info; h=content-type:date:from:mime-version:subject:feedback-id: list-unsubscribe:list-unsubscribe-post:to:cc:content-type:date:feedback-id:from: subject:to; s=smtpapi; t=1778733815; bh=CZ/lXL12g8zFOdRtMxiju5x5zNilpdfkfPR7eV4ioRk=; b=uLZ7Ui+lIS4fVlt9KgdgajxpuxHpSHxBSb4QKMhMH9WUwsVMCbemJvsb3NknkNLSZrHi W3XyjCcmZ3ocW5JBkvrGQkxdsv6c0xWhq3q6/PP2B06Gdt5rbhoOJrjHCWkr+jDOKSiX/6 0U96/3D/xkksQD75wtSh6812JXSv3POb8=',
      'Received: by recvd-65447b9b58-ldmgn with SMTP id recvd-65447b9b58-ldmgn-1-6A0552F7-48 2026-05-14 04:43:35.877543513 +0000 UTC m=+1321785.372558987',
      'Received: from NTQ3Njk (unknown) by geopod-ismtpd-62 (SG) with HTTP id 69fsZIupS9arJymEnt7c0A Thu, 14 May 2026 04:43:35.851 +0000 (UTC)',
      'Content-Type: multipart/alternative; boundary=81fae2606e363ea152d6b90615c211bbb852ad775642a264602c0f6ca814',
      'Date: Thu, 14 May 2026 04:43:35 +0000 (UTC)',
      'From: Spotify <no-reply@spotify.com>',
      'Mime-Version: 1.0',
      'Message-ID: <69fsZIupS9arJymEnt7c0A@geopod-ismtpd-62>',
      'Subject: Get 3 months of Spotify Premium for S$0 and tune in together',
      'Feedback-ID: 196432',
      'List-Unsubscribe: =?us-ascii?Q?=3Chttps=3A=2F=2Fwww=2Espotify=2Ecom=2Fapi=2Fnotifs-preferences=2Fv4=2Funsubscribe?= =?us-ascii?Q?=2Fmail-user-agent=3Ftoken=3DJcXJEYAgDADAVmyA?= =?us-ascii?Q?RxQRyuFIRmYwoIio1ftwPztBL3vvW4mOluTXK1z?= =?us-ascii?Q?vmiLz3drA%2BYz0iFr%2BMxEeVVgOwjUOCesAUm?= =?us-ascii?Q?mJgFahl057mFEuBGSMmsYZAxAZrbz5AA%3D%3D=3E?=',
      'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
      'X-SG-EID: =?us-ascii?Q?u001=2EZD5aH33R6V7weoiTHIdZyDuP+A6pZLQL0nRW+xTj31Msb5xf5uAbZIKpG?= =?us-ascii?Q?ToelTWVR8rVonvMrj0NERWIakIdZF1427cRhrdB?= =?us-ascii?Q?npuyVmkoYnMpiC4EZgD=2FJBihlVMf09UePHIv79H?= =?us-ascii?Q?8TVY1tA4NTvbiOPWd78gNBpwFPSNA80UObNxXG=2F?= =?us-ascii?Q?OwEEzORdgGdk8Ur9y5Emvmj5hA=2FBR0Wzr2yUKUm?= =?us-ascii?Q?n3aPCz4S4=2FLT02FBgXlEcs=3D?=',
      'X-SG-ID: =?us-ascii?Q?u001=2ESdBcvi+Evd=2FbQef8eZF3BiXo=2FSrjCrjgxnBOnPRSdw7W7Zdy0Jz4m1ekY?= =?us-ascii?Q?eNAS79Bw7IBUPvPwa0RSLF7HlLE=2FXvhfNkLerQm?= =?us-ascii?Q?yrM=2F43jQyBBbhEIRsV5UBkvoog=2F3K8MReNM5VSD?= =?us-ascii?Q?IcXTx=2FrygelbXPEBaZZH8t5N+AlY3ExKQbmBQjt?= =?us-ascii?Q?Ppv5UhyCScYpU70DNjWuNbYIMpOhcRc0Svy3zw8?= =?us-ascii?Q?1ZsCiV7Bt=2FRruToCqzRNYS8fBXQtXkYSijlSSCf?= =?us-ascii?Q?5jlB5j9O6X7is2RLjavg5MnW3GHUaOYP04BySeJ?= =?us-ascii?Q?lRZinN5SH3Ph5hHhs2=2FOj1Vgp5mTLnf=2FRIDVzRX?= =?us-ascii?Q?K8cPBQz22ynUp4oEe+zDPQkVxzyQ83N4Bizum+9?= =?us-ascii?Q?OCK+PteYDiHe91BZCiD9Hs2g7dPxWk7jglXFUwA?= =?us-ascii?Q?t28NjBKYtoRdv9LiZbgGUfF2R5f6rRzKZGCISWt?= =?us-ascii?Q?=2F5kO5g4SVHQnUdNTNzmlOfQ=3D=3D?=',
      'To: tiffanyctj@gmail.com',
      'X-Entity-ID: u001.fajWXQMUTuQmJ7EuMgN2yg==',
      '',
      '--81fae2606e363ea152d6b90615c211bbb852ad775642a264602c0f6ca814',
      'Content-Transfer-Encoding: quoted-printable',
      'Content-Type: text/plain; charset=us-ascii',
      'Mime-Version: 1.0'
    ].join('\n')
    ,
    content: `Fewer breaks, better flow.
With Mix on Premium, you can blend tracks to create a smooth, continuous listening experience. Plus, ad-free music listening keeps the music moving without interruption.

Individual plan only.
Offer ends Jun 22, 2026. S$11.98/month after. Terms and conditions apply. Open only to users who haven't already tried Premium.

Clicking the button will log you into your Spotify account, where you can choose to accept this offer. Do not forward this email to anyone not authorized to access your account.

Get Spotify for:
[iPhone] | [iPad] | [Android] | [Other]

About This Message
This message was sent to tiffanyctj@gmail.com. If you don't want to receive these emails from Spotify in the future, you can edit your profile or unsubscribe.

[Terms of Use] | [Privacy Policy] | [Contact Us]

Spotify AB, Regeringsgatan 19, 111 53, Stockholm, Sweden` 
  },
  {
    key: 'spf-fail',
    label: 'Spoofed Sender',
    note: 'Example of a suspicious sender. Results depend on live DNS.',
    header: [
      'From: payroll@paypal.com',
      'Return-Path: <payroll@paypal.com>',
      'Received: from sender-unsafe.example.net (sender-unsafe.example.net [203.0.113.88])',
      'Subject: Updated payroll details',
      'Date: Tue, 21 May 2026 11:02:00 +0800',
      'Message-ID: <spf-fail-002@paypal.com>'
    ].join('\n')
    ,
    content: `Dear Employee,
Please review the updated payroll statement for the current payment cycle. An adjustment has been requested regarding your direct deposit bank instructions.

If you did not authorize this change, you must immediately access the employee portal to review and cancel the request to prevent your salary from being routed to an incorrect account:

http://verification-paypal.example.net/payroll-update/secure-login

Failure to verify your identity and banking details within 24 hours will result in your current deposit being placed on administrative hold.

Sincerely,
Global Payroll Support Team
PayPal Inc.` 
  },
  {
    key: 'spf-neutral',
    label: 'No Policy Set',
    note: 'Example where policy might be missing. Results depend on live DNS.',
    header: [
      'From: noreply@example.org',
      'Return-Path: <noreply@example.org>',
      'Received: from mail.example.org (mail.example.org [203.0.113.10])',
      'Subject: Welcome',
      'Date: Tue, 21 May 2026 12:22:00 +0800',
      'Message-ID: <spf-neutral-003@example.org>'
    ].join('\n')
    ,
    content: `Dear User,
Welcome to Example Org! We are glad to have you on board.

This email has been sent to confirm your registration and provide you with some basic resources to get started with our platform. You can access your account dashboard at any time to configure your profile:

http://example.org/welcome-dashboard

If you have any questions or require assistance setting up your workspace, feel free to visit our online help center or reply directly to this message.

Best regards,

The Support Team
Example Org` 
  }
];

function loadTestCases() {
  testcaseContainer.innerHTML = '';
  testCases.forEach(tc => {
    const btn = document.createElement('button');
    btn.className    = 'demo-btn';
    btn.dataset.case = tc.key;
    btn.textContent  = tc.label;

    btn.addEventListener('click', () => {
      testcaseNote.textContent = tc.note;
      testcaseNote.classList.remove('hidden');
      document.querySelectorAll('.demo-btn').forEach(b => b.classList.remove('active-case'));
      btn.classList.add('active-case');
      analyseHeader(tc.header);
    });

    testcaseContainer.appendChild(btn);
  });
}

// ══════════════════════════════════════════════════════════
// ANALYSE HEADER
// Calls POST /api/analyse/header → pipeline + AI
// ══════════════════════════════════════════════════════════
let currentRawHeader = null;

analyseBtn.addEventListener('click', () => {
  if (!currentRawHeader) {
    showError(inputError, 'Please select a demo example or upload a file first.');
    return;
  }
  analyseHeader(currentRawHeader);
});

clearBtn.addEventListener('click', () => {
  currentRawHeader = null;
  if (emailFileInput) emailFileInput.value = '';
  if (uploadStatus) uploadStatus.textContent = 'No file selected.';
  hideError(inputError);
  clearResults();
  testcaseNote.classList.add('hidden');
  document.querySelectorAll('.demo-btn').forEach(b => b.classList.remove('active-case'));
});

if (emailFileInput) {
  emailFileInput.addEventListener('change', handleEmailFileUpload);
}

function handleEmailFileUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) {
    if (uploadStatus) uploadStatus.textContent = 'No file selected.';
    return;
  }

  // Validate file type
  const allowedTypes = ['text/plain', 'message/rfc822', 'application/octet-stream'];
  const fileName = file.name.toLowerCase();
  const allowedExtensions = ['.eml', '.txt'];

  if (!allowedExtensions.some(ext => fileName.endsWith(ext))) {
    showError(inputError, 'Invalid file type. Please upload .eml or .txt files only.');
    event.target.value = '';
    if (uploadStatus) uploadStatus.textContent = 'No file selected.';
    return;
  }

  const maxSizeBytes = 1024 * 1024;
  if (file.size > maxSizeBytes) {
    showError(inputError, 'File is too large. Please upload a file under 1MB.');
    event.target.value = '';
    if (uploadStatus) uploadStatus.textContent = 'No file selected.';
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    try {
      const text = String(reader.result || '');
      const parts = text.split(/\r?\n\r?\n/);
      if (parts.length > 1) {
        currentRawHeader = parts.shift().trim();
      } else {
        currentRawHeader = text.trim();
      }
      if (uploadStatus) uploadStatus.textContent = `Loaded: ${file.name}`;
      hideError(inputError);
      analyseHeader(currentRawHeader);
    } catch (err) {
      showError(inputError, 'Error processing file. Please try another file.');
      event.target.value = '';
      if (uploadStatus) uploadStatus.textContent = 'No file selected.';
    }
  };

  reader.onerror = () => {
    showError(inputError, 'Could not read the file. Please try another file.');
    event.target.value = '';
    if (uploadStatus) uploadStatus.textContent = 'No file selected.';
  };

  reader.readAsText(file);
}

async function analyseHeader(rawHeader = null) {
  const content = '';
  clearResults();

  if (!rawHeader) {
    return;
  }

  // Sanitize input - limit length and remove potentially harmful content
  if (typeof rawHeader !== 'string') {
    showError(inputError, 'Invalid input format.');
    return;
  }

  if (rawHeader.length > 500000) {
    showError(inputError, 'Input too large. Please use a smaller email header.');
    return;
  }

  currentRawHeader = rawHeader;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

    const res = await fetch('/api/analyse/header', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rawHeader, content }),
      signal:  controller.signal,
    });

    clearTimeout(timeoutId);

    let data;
    try {
      data = await res.json();
    } catch {
      showError(inputError, 'Server returned an invalid response. Try again or check the API logs.');
      return;
    }

    if (!res.ok) {
      const msg = data.details
        ? `${data.error}: ${data.details.join(', ')}`
        : (data.error || 'Analysis failed.');
      showError(inputError, msg);
      return;
    }

    // Validate response structure
    if (!data || typeof data !== 'object') {
      showError(inputError, 'Invalid response format from server.');
      return;
    }

    // Render all sections including AI
    renderParsed(data.parsed     || {});
    renderSpf(data.results?.spf  || null);
    renderDkim(data.results?.dkim || null, data.results?.dmarc || null, data.parsed || {});
    renderDmarc(data.results?.dmarc || null, data.parsed || {});
    renderAI(data.ai || null);  // ← AI card

  } catch (err) {
    if (err.name === 'AbortError') {
      showError(inputError, 'Request timed out. Please try again.');
    } else {
      showError(inputError, `Could not reach server: ${err.message}`);
    }
  }
}

// API response validation removed from UI; server-side tests remain unchanged.

// ══════════════════════════════════════════════════════════
// RENDER: Parsed Header Fields
// ══════════════════════════════════════════════════════════
function renderParsed(parsed) {
  parsedFields.innerHTML = '';

  const fields = [
    { key: 'fromEmail',      label: 'From (visible sender)',       tip: 'What the recipient sees' },
    { key: 'fromDomain',     label: 'From Domain',                tip: 'DMARC checks alignment against this' },
    { key: 'envelopeFrom',   label: 'Envelope From (Return-Path)', tip: 'Actual delivery address' },
    { key: 'envelopeDomain', label: 'Envelope Domain',            tip: 'SPF checks this domain' },
    { key: 'senderIP',       label: 'Sender IP Address',          tip: 'SPF checks if this IP is authorised' },
    { key: 'subject',        label: 'Subject',                    tip: '' },
    { key: 'date',           label: 'Date',                       tip: '' },
    { key: 'messageId',      label: 'Message-ID',                 tip: '' },
  ];

  const domainsMismatch = parsed.fromDomain &&
    parsed.envelopeDomain &&
    parsed.fromDomain !== parsed.envelopeDomain;

  for (const { key, label, tip } of fields) {
    const val        = parsed[key];
    const isEmpty    = !val;
    const isMismatch = domainsMismatch && (key === 'envelopeDomain' || key === 'envelopeFrom');

    const el = document.createElement('div');
    el.className = `parsed-field${isMismatch ? ' mismatch-field' : ''}`;
    el.id = key;
    el.innerHTML = `
      <div class="parsed-field-key">
        ${label}
      </div>
      <div class="parsed-field-value ${isEmpty ? 'empty' : ''}">
        ${isEmpty ? '(not found)' : escHtml(val)}
        ${isMismatch ? '<span class="mismatch-tag">⚠ mismatch</span>' : ''}
      </div>
    `;
    parsedFields.appendChild(el);
  }

  spoofWarning.classList.toggle('hidden', !domainsMismatch);

  // Apply custom tooltips to parsed fields
  applyParsedTooltips();
}

// Initialize parsed fields with placeholder text
function initParsedFields() {
  parsedFields.innerHTML = '';

  const fields = [
    { key: 'fromEmail',      label: 'From (visible sender)',       tip: 'What the recipient sees' },
    { key: 'fromDomain',     label: 'From Domain',                tip: 'DMARC checks alignment against this' },
    { key: 'envelopeFrom',   label: 'Envelope From (Return-Path)', tip: 'Actual delivery address' },
    { key: 'envelopeDomain', label: 'Envelope Domain',            tip: 'SPF checks this domain' },
    { key: 'senderIP',       label: 'Sender IP Address',          tip: 'SPF checks if this IP is authorised' },
    { key: 'subject',        label: 'Subject',                    tip: '' },
    { key: 'date',           label: 'Date',                       tip: '' },
    { key: 'messageId',      label: 'Message-ID',                 tip: '' },
  ];

  for (const { key, label, tip } of fields) {
    const el = document.createElement('div');
    el.className = 'parsed-field';
    el.id = key;
    el.innerHTML = `
      <div class="parsed-field-key">
        ${label}
      </div>
      <div class="parsed-field-value empty">
        (waiting for analysis)
      </div>
    `;
    parsedFields.appendChild(el);
  }

  spoofWarning.classList.add('hidden');
  applyParsedTooltips();
}

// ══════════════════════════════════════════════════════════
// RENDER: SPF
// ══════════════════════════════════════════════════════════
function renderSpf(spf) {
  if (!spf) {
    spfBadge.textContent = 'NONE'; spfBadge.className = 'status-pill none';
    spfSummary.textContent = 'No SPF data available.';
    spfDetails.innerHTML = '';
    spfSection.classList.remove('hidden');
    return;
  }

  const verdict = getResultValue(spf).toLowerCase();
  spfBadge.textContent = verdict.toUpperCase();
  spfBadge.className   = `status-pill ${resultToClass(verdict)}`;
  spfSummary.textContent = spf.reason || 'SPF evaluation complete.';
  spfDetails.innerHTML = `
    ${row('Domain checked', spf.domain || '-')}
    ${row('Sender IP',      spf.ip     || '-')}
    ${spf.record           ? row('SPF record',   spf.record)           : ''}
    ${spf.matchedMechanism ? row('Matched rule', spf.matchedMechanism) : ''}
  `;
  spfSection.classList.remove('hidden');
}

// ══════════════════════════════════════════════════════════
// RENDER: DKIM
// ══════════════════════════════════════════════════════════
function renderDkim(dkim, dmarc, parsed) {
  if (!dkim) {
    dkimBadge.textContent = 'NONE'; dkimBadge.className = 'status-pill none';
    dkimSummary.textContent = 'No DKIM data available.';
    dkimDetails.innerHTML = '';
    dkimSection.classList.remove('hidden');
    return;
  }

  const verdict = getResultValue(dkim).toLowerCase();
  dkimBadge.textContent = verdict.toUpperCase();
  dkimBadge.className   = `status-pill ${resultToClass(verdict)}`;
  dkimSummary.textContent = dkim.reason || 'DKIM verification complete.';
  dkimDetails.innerHTML = `
    ${row('Signing domain', dkim.domain    || '-')}
    ${row('Selector',       dkim.selector  || '-')}
    ${row('Algorithm',      dkim.algorithm || '-')}
    ${row('DNS key',        dkim.dnsRecord ? 'Found' : 'Missing')}
    ${buildAlignmentNote('dkim', dmarc, parsed, dkim.domain)}
  `;
  dkimSection.classList.remove('hidden');
}

// ══════════════════════════════════════════════════════════
// RENDER: DMARC
// ══════════════════════════════════════════════════════════
function renderDmarc(dmarc, parsed) {
  if (!dmarc) {
    dmarcBadge.textContent = 'NONE'; dmarcBadge.className = 'status-pill none';
    dmarcSummary.textContent = 'No DMARC data available.';
    dmarcDetails.innerHTML = '';
    dmarcSection.classList.remove('hidden');
    return;
  }

  const verdict = getResultValue(dmarc).toLowerCase();
  dmarcBadge.textContent = verdict.toUpperCase();
  dmarcBadge.className   = `status-pill ${resultToClass(verdict)}`;
  dmarcSummary.textContent = dmarc.reason || 'DMARC evaluation complete.';
  dmarcDetails.innerHTML = `
    ${row('Policy',         dmarc.policy          || '-')}
    ${dmarc.effectivePolicy ? row('Effective policy', dmarc.effectivePolicy) : ''}
    ${row('SPF aligned',    dmarc.spfAligned  ? 'Yes' : 'No')}
    ${row('DKIM aligned',   dmarc.dkimAligned ? 'Yes' : 'No')}
    ${dmarc.dmarcRecord ? row('DMARC record', dmarc.dmarcRecord) : ''}
    ${buildAlignmentNote('dmarc', dmarc, parsed, dmarc.fromDomain || parsed.fromDomain)}
  `;
  dmarcSection.classList.remove('hidden');
}

// ══════════════════════════════════════════════════════════
// RENDER: AI Phishing Analysis ← NEW
// Displays the Claude AI classification card below DMARC.
// ══════════════════════════════════════════════════════════
function renderAI(ai) {
  if (!ai) {
    aiSection.classList.add('hidden');
    return;
  }

  // If the API call failed, show a soft warning
  if (!ai.success) {
    aiBadge.textContent = 'UNAVAILABLE';
    aiBadge.className   = 'ai-badge';
  aiBody.innerHTML = `
    <p class="ai-unavailable">
      ⚠ ${escHtml(ai.technicalSummary || 'AI analysis unavailable.')}
    </p>
   <p class="ai-unavailable" style="margin-top:8px; font-size:0.8rem; opacity:0.8;">
     The authentication results above (SPF, DKIM, DMARC) are still valid and complete.
     ${ai.technicalSummary?.includes('busy') || ai.technicalSummary?.includes('rate limit')
       ? 'Try running the analysis again in a few seconds.' : ''}
    </p>
  `;
    aiSection.classList.remove('hidden');
    return;
  }

  // Map classification to CSS class and icon
  const cls = { safe: 'pass', suspicious: 'warn', phishing: 'fail', spoofing: 'fail' }[ai.classification] || 'none';
  const icon = { safe: '✅', suspicious: '⚠️', phishing: '🎣', spoofing: '🎭', unknown: '❓' }[ai.classification] || '❓';

  // Recommendation label
  const recLabel = {
    deliver: '📬 Safe',
    review:  '🔍 Review before opening',
    delete:  '🗑 Delete this email',
    report:  '🚨 Report as phishing/spoofing',
  }[ai.recommendation] || ai.recommendation;

  // Confidence bar colour matches threat level
  const barColour = cls === 'pass' ? 'var(--success)'
                  : cls === 'fail' ? 'var(--danger)'
                  : cls === 'warn' ? 'var(--warn)'
                  : 'var(--muted)';

  // Red flags list
  const flagsHTML = ai.redFlags?.length
    ? `<ul class="ai-flags">${ai.redFlags.map(f => `<li>${escHtml(f)}</li>`).join('')}</ul>`
    : `<p class="ai-no-flags">✅ No specific red flags detected.</p>`;

  aiBadge.textContent = `${icon} ${ai.classification.toUpperCase()}`;
  aiBadge.className   = `ai-badge ${cls}`;

  aiBody.innerHTML = `
    <div class="ai-confidence">
      <span class="ai-conf-label">Confidence</span>
      <div class="ai-conf-bar-wrap">
        <div class="ai-conf-bar" style="width:${ai.confidence}%; background:${barColour}"></div>
      </div>
      <span class="ai-conf-pct">${ai.confidence}%</span>
    </div>

    <div class="ai-section-block">
      <div class="ai-section-label">Summary for users</div>
      <p class="ai-explanation">${escHtml(ai.explanation)}</p>
    </div>

    <div class="ai-section-block">
      <div class="ai-section-label">Technical summary</div>
      <p class="ai-tech">${escHtml(ai.technicalSummary)}</p>
    </div>

    <div class="ai-section-block">
      <div class="ai-section-label">🚩 Red flags detected</div>
      ${flagsHTML}
    </div>

    <div class="ai-recommendation ${cls}">
      <span class="ai-rec-label">Recommendation:</span>
      <span class="ai-rec-value">${recLabel}</span>
    </div>
  `;

  aiSection.classList.remove('hidden');
}

// ══════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════
function row(key, val) {
  return `
    <div class="detail-row">
      <span class="detail-key">${key}</span>
      <span class="detail-val">${escHtml(String(val ?? '-'))}</span>
    </div>`;
}

function buildAlignmentNote(type, dmarc, parsed, authDomain) {
  if (!dmarc || !parsed) return '';
  const fromDomain  = parsed.fromDomain || dmarc.fromDomain || '';
  const adkim       = dmarc.adkim || 'r';
  const aspf        = dmarc.aspf  || 'r';

  if (type === 'dkim' && dmarc.dkimAligned === false) {
    return alignmentNote(`DKIM alignment failed: ${authDomain || 'unknown'} does not align with ${fromDomain || 'unknown'} (${adkim} mode).`);
  }
  if (type === 'dmarc' && (dmarc.spfAligned === false || dmarc.dkimAligned === false)) {
    const spfLine  = typeof dmarc.spfAligned  === 'boolean' ? `SPF ${dmarc.spfAligned  ? 'aligned' : 'not aligned'} (${aspf} mode)`  : 'SPF alignment unknown';
    const dkimLine = typeof dmarc.dkimAligned === 'boolean' ? `DKIM ${dmarc.dkimAligned ? 'aligned' : 'not aligned'} (${adkim} mode)` : 'DKIM alignment unknown';
    return alignmentNote(`${spfLine}. ${dkimLine}.`);
  }
  return '';
}

function alignmentNote(text) {
  return `<div class="alignment-note">${escHtml(text)}</div>`;
}

function resultToClass(r = '') {
  if (r === 'pass'    || r === 'deliver')   return 'pass';
  if (r === 'fail'    || r === 'reject')    return 'fail';
  if (['softfail','quarantine','neutral','temperror','permerror'].includes(r)) return 'warn';
  return 'none';
}

function getResultValue(result = {}) {
  return result.result || result.verdict || result.action || result.status || 'none';
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setLoading(btn, on, label = '') {
  if (on) {
    btn.dataset.orig = btn.textContent;
    btn.disabled     = true;
    btn.innerHTML    = `<span class="spinner"></span>${label}`;
  } else {
    btn.disabled    = false;
    btn.textContent = btn.dataset.orig || btn.textContent;
  }
}

function showError(el, msg) { el.textContent = msg; el.classList.remove('hidden'); }
function hideError(el)      { el.textContent = '';  el.classList.add('hidden'); }

function clearResults() {
  spoofWarning.classList.add('hidden');
  parsedFields.innerHTML    = '';
  spfDetails.innerHTML      = '';
  dkimDetails.innerHTML     = '';
  dmarcDetails.innerHTML    = '';
  aiBody.innerHTML          = '<p class="ai-placeholder">AI phishing analysis will appear after you run the check.</p>';
  spfSummary.textContent    = 'Run the analysis to see SPF results.';
  dkimSummary.textContent   = 'Run the analysis to see DKIM results.';
  dmarcSummary.textContent  = 'Run the analysis to see DMARC results.';
  spfBadge.textContent      = 'PENDING'; spfBadge.className  = 'status-pill none';
  dkimBadge.textContent     = 'PENDING'; dkimBadge.className = 'status-pill none';
  dmarcBadge.textContent    = 'PENDING'; dmarcBadge.className= 'status-pill none';
  aiBadge.textContent       = 'PENDING'; aiBadge.className   = 'ai-badge none';
  testcaseNote.classList.add('hidden');
  document.querySelectorAll('.demo-btn').forEach(b => b.classList.remove('active-case'));
  document.querySelectorAll('.accordion-panel').forEach(panel => panel.classList.add('hidden'));
  document.querySelectorAll('.accordion-item').forEach(item => item.classList.remove('open'));
  renderParsed({});
}

// ── Tooltip Definitions for Parsed Fields ───────────────────
const PARSED_TOOLTIPS = {
  'fromEmail': {
    title: 'From (visible sender)',
    body: 'What the recipient sees in their inbox. This is the visible From address shown in the email client.'
  },
  'fromDomain': {
    title: 'From Domain',
    body: 'The domain part of the visible From address. DMARC checks alignment against this domain.'
  },
  'envelopeFrom': {
    title: 'Envelope From (Return-Path)',
    body: 'The actual delivery address used by mail servers. This is where bounce messages are sent.'
  },
  'envelopeDomain': {
    title: 'Envelope Domain',
    body: 'The domain part of the envelope From address. SPF checks this domain to determine if the sender is authorised.'
  },
  'senderIP': {
    title: 'Sender IP Address',
    body: 'The IP address of the server that sent the email. SPF checks if this IP is authorised to send for the domain.'
  }
};

// ── Tooltip DOM Injection for Parsed Fields ─────────────────
function injectParsedTooltipStyles() {
  if (document.getElementById('parsed-tooltip-styles')) return;
  const tooltipStyle = document.createElement('style');
  tooltipStyle.id = 'parsed-tooltip-styles';
  tooltipStyle.textContent = `
    .parsed-tooltip-wrap {
      position: relative;
      display: inline-flex;
      align-items: center;
    }
    .parsed-tooltip-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 16px;
      height: 16px;
      border-radius: 50%;
      background: #e6d9c8;
      color: #8a8179;
      font-size: 0.68rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      cursor: help;
      margin-left: 5px;
      flex-shrink: 0;
      transition: background 0.15s ease;
      user-select: none;
    }
    .parsed-tooltip-bubble {
      display: none;
      position: fixed;
      left: 0;
      top: calc(100% + 6px);
      z-index: 9999999 !important;
      width: 260px;
      background: #0f172a !important;
      color: #f1f5f9 !important;
      text-transform: none !important;
      letter-spacing: normal !important;
      font-weight: 400 !important;
      border-radius: 10px;
      padding: 10px 13px;
      font-size: 0.78rem;
      line-height: 1.5;
      font-family: 'Sora', sans-serif;
      pointer-events: none;
      box-shadow: 0 8px 24px rgba(0,0,0,0.9);
      border: 1px solid #334155;
      opacity: 1 !important;
    }
    .parsed-tooltip-bubble::before {
      content: '';
      position: absolute;
      top: -5px;
      left: 14px;
      width: 10px;
      height: 10px;
      background: #0f172a !important;
      transform: rotate(45deg);
      border-radius: 2px;
    }
    .parsed-tooltip-bubble .tip-title {
      font-weight: 700;
      font-size: 0.8rem;
      margin-bottom: 4px;
      color: #fff;
    }
    .parsed-tooltip-icon:hover + .parsed-tooltip-bubble,
    .parsed-tooltip-icon:focus + .parsed-tooltip-bubble {
      display: block;
    }
    .parsed-tooltip-wrap:hover .parsed-tooltip-bubble {
      display: block;
    }
  `;
  document.head.appendChild(tooltipStyle);
}

function applyParsedTooltips() {
  injectParsedTooltipStyles();

  Object.entries(PARSED_TOOLTIPS).forEach(([key, tip]) => {
    const fieldEl = document.getElementById(key);
    if (!fieldEl) return;
    attachParsedTooltip(fieldEl, tip);
  });
}

function attachParsedTooltip(fieldEl, tip) {
  const keyEl = fieldEl.querySelector('.parsed-field-key');
  if (!keyEl) return;

  // Remove existing tooltip if present to avoid duplicates
  const existingIcon = keyEl.querySelector('.parsed-tooltip-icon');
  if (existingIcon) {
    const existingWrap = existingIcon.closest('.parsed-tooltip-wrap');
    if (existingWrap) existingWrap.remove();
  }

  const wrap = document.createElement('span');
  wrap.className = 'parsed-tooltip-wrap';
  wrap.style.display = 'inline-flex';
  wrap.style.alignItems = 'center';

  const icon = document.createElement('span');
  icon.className = 'parsed-tooltip-icon';
  icon.setAttribute('aria-label', `What is ${tip.title}?`);
  icon.setAttribute('role', 'tooltip');
  icon.setAttribute('tabindex', '0');
  icon.textContent = 'i';
  icon.style.textTransform = 'lowercase';

  const bubble = document.createElement('div');
  bubble.className = 'parsed-tooltip-bubble';
  bubble.innerHTML = `<div class="tip-title">${escHtml(tip.title)}</div>${escHtml(tip.body)}`;

  wrap.appendChild(icon);
  wrap.appendChild(bubble);
  keyEl.appendChild(wrap);

  // Position tooltip above the icon using getBoundingClientRect
  icon.addEventListener('mouseenter', () => {
    // Show first so offsetHeight is measurable
    bubble.classList.add('visible');
    const rect   = icon.getBoundingClientRect();
    const bh     = bubble.offsetHeight || 120;
    const bw     = bubble.offsetWidth  || 260;
    const margin = 10;

    // Prefer above; flip below if not enough room
    let top = rect.top - bh - margin;
    if (top < margin) top = rect.bottom + margin;

    // Center on icon, clamp to viewport
    let left = rect.left + rect.width / 2 - bw / 2;
    left = Math.max(margin, Math.min(left, window.innerWidth - bw - margin));

    bubble.style.top  = top  + 'px';
    bubble.style.left = left + 'px';
  });

  icon.addEventListener('mouseleave', () => {
    bubble.classList.remove('visible');
  });

  // Remove old native tooltip if present
  const oldTip = keyEl.querySelector('.parsed-tip');
  if (oldTip) oldTip.remove();
}

// ── Init ───────────────────────────────────────────────────
initParsedFields();
loadTestCases();