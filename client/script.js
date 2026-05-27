/**
 * script.js — Frontend Logic (Tiffany)
 * Connected to /api/analyse/header for header parsing and authentication evaluation.
 * AI phishing analysis card added — powered by Claude via aiChecker.js
 */

// ── DOM refs ───────────────────────────────────────────────
const headerInput   = document.getElementById('header-input');
const contentInput  = document.getElementById('content-input');
const analyseBtn    = document.getElementById('analyse-btn');
const clearBtn      = document.getElementById('clear-btn');
const inputError    = document.getElementById('input-error');

const parsedSection = document.getElementById('parsed-section');
const parsedFields  = document.getElementById('parsed-fields');
const spoofWarning  = document.getElementById('spoof-warning');

const spfSection    = document.getElementById('spf-section');
const spfBadge      = document.getElementById('spf-badge');
const spfSummary    = document.getElementById('spf-summary');
const spfDetails    = document.getElementById('spf-details');

const dkimSection   = document.getElementById('dkim-section');
const dkimBadge     = document.getElementById('dkim-badge');
const dkimSummary   = document.getElementById('dkim-summary');
const dkimDetails   = document.getElementById('dkim-details');

const dmarcSection  = document.getElementById('dmarc-section');
const dmarcBadge    = document.getElementById('dmarc-badge');
const dmarcSummary  = document.getElementById('dmarc-summary');
const dmarcDetails  = document.getElementById('dmarc-details');

const validationCard = document.getElementById('validation-card');
const validationList = document.getElementById('validation-list');

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
      headerInput.value = tc.header;
      testcaseNote.textContent = tc.note;
      testcaseNote.classList.remove('hidden');
      document.querySelectorAll('.demo-btn').forEach(b => b.classList.remove('active-case'));
      btn.classList.add('active-case');
    });

    testcaseContainer.appendChild(btn);
  });
}

// ══════════════════════════════════════════════════════════
// ANALYSE HEADER
// Calls POST /api/analyse/header → pipeline + AI
// ══════════════════════════════════════════════════════════
analyseBtn.addEventListener('click', analyseHeader);
clearBtn.addEventListener('click', () => {
  headerInput.value = '';
  if (contentInput) contentInput.value = '';
  hideError(inputError);
  clearResults();
});
headerInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.ctrlKey) analyseHeader();
});

async function analyseHeader() {
  const rawHeader = headerInput.value.trim();
  const content = contentInput ? contentInput.value.trim() : '';
  clearResults();
  hideError(inputError);

  if (!rawHeader) {
    showError(inputError, 'Please paste an email header first, or click a demo button.');
    return;
  }

  setLoading(analyseBtn, true, 'Analysing...');

  try {
    const res = await fetch('/api/analyse/header', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rawHeader, content }),
    });

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

    // Render all sections including AI
    renderValidation(validateResponse(data));
    renderParsed(data.parsed     || {});
    renderSpf(data.results?.spf  || null);
    renderDkim(data.results?.dkim || null, data.results?.dmarc || null, data.parsed || {});
    renderDmarc(data.results?.dmarc || null, data.parsed || {});
    renderAI(data.ai || null);  // ← AI card

  } catch (err) {
    showError(inputError, `Could not reach server: ${err.message}`);
  } finally {
    setLoading(analyseBtn, false);
  }
}

// ══════════════════════════════════════════════════════════
// RENDER: API Response Validation
// ══════════════════════════════════════════════════════════
function renderValidation(missing) {
  validationList.innerHTML = '';

  if (missing.length === 0) {
    const li = document.createElement('li');
    li.textContent = '✅ All required fields are present.';
    validationList.appendChild(li);
  } else {
    missing.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      validationList.appendChild(li);
    });
  }

  validationCard.classList.remove('hidden');
}

function validateResponse(data) {
  const missing = [];
  if (!data || typeof data !== 'object') return ['Response is missing or invalid.'];
  if (!data.parsed)          missing.push('Missing: parsed');
  if (!data.results)         missing.push('Missing: results');
  if (!data.results?.spf)    missing.push('Missing: results.spf');
  if (!data.results?.dkim)   missing.push('Missing: results.dkim');
  if (!data.results?.dmarc)  missing.push('Missing: results.dmarc');

  ['fromEmail','fromDomain','envelopeFrom','envelopeDomain','senderIP'].forEach(k => {
    if (!data.parsed?.[k]) missing.push(`Missing: parsed.${k}`);
  });
  ['result','domain','ip'].forEach(k => {
    if (!data.results?.spf?.[k]) missing.push(`Missing: results.spf.${k}`);
  });
  ['result','domain'].forEach(k => {
    if (!data.results?.dkim?.[k]) missing.push(`Missing: results.dkim.${k}`);
  });
  ['verdict','policy'].forEach(k => {
    if (!data.results?.dmarc?.[k]) missing.push(`Missing: results.dmarc.${k}`);
  });

  return missing;
}

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
    el.innerHTML = `
      <div class="parsed-field-key">
        ${label}
        ${tip ? `<span class="parsed-tip" title="${tip}">?</span>` : ''}
      </div>
      <div class="parsed-field-value ${isEmpty ? 'empty' : ''}">
        ${isEmpty ? '(not found)' : escHtml(val)}
        ${isMismatch ? '<span class="mismatch-tag">⚠ mismatch</span>' : ''}
      </div>
    `;
    parsedFields.appendChild(el);
  }

  spoofWarning.classList.toggle('hidden', !domainsMismatch);
  parsedSection.classList.remove('hidden');
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
    aiBody.innerHTML    = `<p class="ai-unavailable">⚠ AI analysis unavailable — ${escHtml(ai.technicalSummary || 'Check server logs.')}</p>`;
    aiSection.classList.remove('hidden');
    return;
  }

  // Map classification to CSS class and icon
  const cls = { safe: 'pass', suspicious: 'warn', phishing: 'fail', spoofing: 'fail' }[ai.classification] || 'none';
  const icon = { safe: '✅', suspicious: '⚠️', phishing: '🎣', spoofing: '🎭', unknown: '❓' }[ai.classification] || '❓';

  // Recommendation label
  const recLabel = {
    deliver: '📬 Safe to deliver',
    review:  '🔍 Review before opening',
    delete:  '🗑 Delete this email',
    report:  '🚨 Report as phishing',
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
      <div class="ai-section-label">📋 Summary for users</div>
      <p class="ai-explanation">${escHtml(ai.explanation)}</p>
    </div>

    <div class="ai-section-block">
      <div class="ai-section-label">🔧 Technical summary</div>
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
  validationCard.classList.add('hidden');
  parsedSection.classList.add('hidden');
  spfSection.classList.add('hidden');
  dkimSection.classList.add('hidden');
  dmarcSection.classList.add('hidden');
  aiSection.classList.add('hidden');       // ← clear AI card too
  spoofWarning.classList.add('hidden');
  parsedFields.innerHTML    = '';
  spfDetails.innerHTML      = '';
  dkimDetails.innerHTML     = '';
  dmarcDetails.innerHTML    = '';
  aiBody.innerHTML          = '';
  spfSummary.textContent    = 'Run the analysis to see SPF results.';
  dkimSummary.textContent   = 'Run the analysis to see DKIM results.';
  dmarcSummary.textContent  = 'Run the analysis to see DMARC results.';
  spfBadge.textContent      = '-'; spfBadge.className  = 'status-pill';
  dkimBadge.textContent     = '-'; dkimBadge.className = 'status-pill';
  dmarcBadge.textContent    = '-'; dmarcBadge.className= 'status-pill';
  aiBadge.textContent       = '—'; aiBadge.className   = 'ai-badge';
  validationList.innerHTML  = '';
  testcaseNote.classList.add('hidden');
  document.querySelectorAll('.demo-btn').forEach(b => b.classList.remove('active-case'));
}

// ── Init ───────────────────────────────────────────────────
loadTestCases();