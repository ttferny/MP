/**
 * script.js — Frontend Logic (Tiffany)
 * Connected to /api/analyse/header for header parsing and authentication evaluation.
 */

// ── DOM refs ───────────────────────────────────────────────
const headerInput     = document.getElementById('header-input');
const analyseBtn      = document.getElementById('analyse-btn');
const clearBtn        = document.getElementById('clear-btn');
const inputError      = document.getElementById('input-error');

const parsedSection   = document.getElementById('parsed-section');
const parsedFields    = document.getElementById('parsed-fields');
const spoofWarning    = document.getElementById('spoof-warning');

const spfSection      = document.getElementById('spf-section');
const spfBadge        = document.getElementById('spf-badge');
const spfSummary      = document.getElementById('spf-summary');
const spfDetails      = document.getElementById('spf-details');

const dkimSection     = document.getElementById('dkim-section');
const dkimBadge       = document.getElementById('dkim-badge');
const dkimSummary     = document.getElementById('dkim-summary');
const dkimDetails     = document.getElementById('dkim-details');

const dmarcSection    = document.getElementById('dmarc-section');
const dmarcBadge      = document.getElementById('dmarc-badge');
const dmarcSummary    = document.getElementById('dmarc-summary');
const dmarcDetails    = document.getElementById('dmarc-details');

const validationCard  = document.getElementById('validation-card');
const validationList  = document.getElementById('validation-list');

const testcaseContainer = document.getElementById('testcase-container');
const testcaseNote      = document.getElementById('testcase-note');

// ══════════════════════════════════════════════════════════
// TEST CASES
// ══════════════════════════════════════════════════════════
const testCases = [
  {
    key: 'spf-pass',
    label: 'Authorized Sender',
    note: 'Example for a legitimate sender. Results depend on live DNS.',
    header: [
      'From: alerts@google.com',
      'Return-Path: <alerts@google.com>',
      'Received: from mail-io1-f65.google.com (mail-io1-f65.google.com [209.85.166.65])',
      'Subject: Security alert',
      'Date: Tue, 21 May 2026 10:12:00 +0800',
      'Message-ID: <spf-pass-001@google.com>'
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
    btn.className = 'demo-btn';
    btn.dataset.case = tc.key;
    btn.textContent = tc.label;

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
// Calls POST /api/analyse/header with the pasted raw header
// ══════════════════════════════════════════════════════════
analyseBtn.addEventListener('click', analyseHeader);
clearBtn.addEventListener('click', () => {
  headerInput.value = '';
  hideError(inputError);
  clearResults();
});
headerInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.ctrlKey) analyseHeader();
});

async function analyseHeader() {
  const rawHeader = headerInput.value.trim();
  clearResults();
  hideError(inputError);

  if (!rawHeader) {
    showError(inputError, 'Please paste an email header first, or click a demo button.');
    return;
  }

  setLoading(analyseBtn, true, 'Analysing...');

  try {
    const res  = await fetch('/api/analyse/header', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rawHeader }),
    });
    let data;
    try {
      data = await res.json();
    } catch (parseErr) {
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

    renderValidation(validateResponse(data));
    renderParsed(data.parsed || {});
    renderSpf(data.results?.spf || null);
    renderDkim(data.results?.dkim || null, data.results?.dmarc || null, data.parsed || {});
    renderDmarc(data.results?.dmarc || null, data.parsed || {});

  } catch (err) {
    showError(inputError, `Could not reach server: ${err.message}`);
  } finally {
    setLoading(analyseBtn, false);
  }
}

// ══════════════════════════════════════════════════════════
// RENDER FUNCTIONS
// ══════════════════════════════════════════════════════════

function renderValidation(missing) {
  validationList.innerHTML = '';

  if (missing.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'All required fields are present.';
    validationList.appendChild(li);
    validationCard.classList.remove('hidden');
    return;
  }

  missing.forEach(item => {
    const li = document.createElement('li');
    li.textContent = item;
    validationList.appendChild(li);
  });

  validationCard.classList.remove('hidden');
}

function validateResponse(data) {
  const missing = [];

  if (!data || typeof data !== 'object') {
    return ['Response is missing or invalid.'];
  }

  if (!data.parsed) missing.push('Missing: parsed');
  if (!data.results) missing.push('Missing: results');
  if (!data.results?.spf) missing.push('Missing: results.spf');
  if (!data.results?.dkim) missing.push('Missing: results.dkim');
  if (!data.results?.dmarc) missing.push('Missing: results.dmarc');

  const parsed = data.parsed || {};
  ['fromEmail', 'fromDomain', 'envelopeFrom', 'envelopeDomain', 'senderIP'].forEach(key => {
    if (!parsed[key]) missing.push(`Missing: parsed.${key}`);
  });

  const spf = data.results?.spf || {};
  ['result', 'domain', 'ip'].forEach(key => {
    if (!spf[key]) missing.push(`Missing: results.spf.${key}`);
  });

  const dkim = data.results?.dkim || {};
  ['result', 'domain'].forEach(key => {
    if (!dkim[key]) missing.push(`Missing: results.dkim.${key}`);
  });

  const dmarc = data.results?.dmarc || {};
  ['verdict', 'policy'].forEach(key => {
    if (!dmarc[key]) missing.push(`Missing: results.dmarc.${key}`);
  });

  return missing;
}

// ── Parsed fields ──────────────────────────────────────────
function renderParsed(parsed) {
  parsedFields.innerHTML = '';

  const fields = [
    { key: 'fromEmail',      label: 'From (visible sender)',           tip: 'What the recipient sees' },
    { key: 'fromDomain',     label: 'From Domain',                    tip: 'DMARC checks alignment against this' },
    { key: 'envelopeFrom',   label: 'Envelope From (Return-Path)',     tip: 'Actual delivery address' },
    { key: 'envelopeDomain', label: 'Envelope Domain',                tip: 'SPF checks this domain' },
    { key: 'senderIP',       label: 'Sender IP Address',              tip: 'SPF checks if this IP is authorised' },
    { key: 'subject',        label: 'Subject',                        tip: '' },
    { key: 'date',           label: 'Date',                           tip: '' },
    { key: 'messageId',      label: 'Message-ID',                     tip: '' }
  ];

  const domainsMismatch = parsed.fromDomain &&
    parsed.envelopeDomain &&
    parsed.fromDomain !== parsed.envelopeDomain;

  for (const { key, label, tip } of fields) {
    const val      = parsed[key];
    const isEmpty  = !val;
    const isMismatch = domainsMismatch && (key === 'envelopeDomain' || key === 'envelopeFrom');

    const el = document.createElement('div');
    el.className = `parsed-field${isMismatch ? ' mismatch-field' : ''}`;
    el.innerHTML = `
      <div class="parsed-field-key">${label}${tip ? `<span class="parsed-tip" title="${tip}">?</span>` : ''}</div>
      <div class="parsed-field-value ${isEmpty ? 'empty' : ''}">
        ${isEmpty ? '(not found)' : escHtml(val)}
        ${isMismatch ? '<span class="mismatch-tag">⚠ mismatch</span>' : ''}
      </div>
    `;
    parsedFields.appendChild(el);
  }

  // Show spoofing warning if domains differ
  spoofWarning.classList.toggle('hidden', !domainsMismatch);
  parsedSection.classList.remove('hidden');
}
// ── SPF ───────────────────────────────────────────────────
function renderSpf(spf) {
  if (!spf) {
    spfBadge.textContent = 'NONE';
    spfBadge.className = 'status-pill none';
    spfSummary.textContent = 'No SPF data available.';
    spfDetails.innerHTML = '';
    spfSection.classList.remove('hidden');
    return;
  }

  const verdict = getResultValue(spf).toLowerCase();
  const cls = resultToClass(verdict);

  spfBadge.textContent = verdict.toUpperCase();
  spfBadge.className = `status-pill ${cls}`;
  spfSummary.textContent = spf.reason || 'SPF evaluation complete.';
  spfDetails.innerHTML = `
    ${row('Domain checked', spf.domain || '-')}
    ${row('Sender IP', spf.ip || '-')}
    ${spf.record ? row('SPF record', spf.record) : ''}
    ${spf.matchedMechanism ? row('Matched rule', spf.matchedMechanism) : ''}
  `;

  spfSection.classList.remove('hidden');
}

// ── DKIM ──────────────────────────────────────────────────
function renderDkim(dkim, dmarc, parsed) {
  if (!dkim) {
    dkimBadge.textContent = 'NONE';
    dkimBadge.className = 'status-pill none';
    dkimSummary.textContent = 'No DKIM data available.';
    dkimDetails.innerHTML = '';
    dkimSection.classList.remove('hidden');
    return;
  }

  const verdict = getResultValue(dkim).toLowerCase();
  const cls = resultToClass(verdict);
  const alignmentNote = buildAlignmentNote('dkim', dmarc, parsed, dkim.domain);

  dkimBadge.textContent = verdict.toUpperCase();
  dkimBadge.className = `status-pill ${cls}`;
  dkimSummary.textContent = dkim.reason || 'DKIM verification complete.';
  dkimDetails.innerHTML = `
    ${row('Signing domain', dkim.domain || '-')}
    ${row('Selector', dkim.selector || '-')}
    ${row('Algorithm', dkim.algorithm || '-')}
    ${row('DNS key', dkim.dnsRecord ? 'Found' : 'Missing')}
    ${alignmentNote}
  `;

  dkimSection.classList.remove('hidden');
}

// ── DMARC ────────────────────────────────────────────────
function renderDmarc(dmarc, parsed) {
  if (!dmarc) {
    dmarcBadge.textContent = 'NONE';
    dmarcBadge.className = 'status-pill none';
    dmarcSummary.textContent = 'No DMARC data available.';
    dmarcDetails.innerHTML = '';
    dmarcSection.classList.remove('hidden');
    return;
  }

  const verdict = getResultValue(dmarc).toLowerCase();
  const cls = resultToClass(verdict);
  const alignmentNote = buildAlignmentNote('dmarc', dmarc, parsed, dmarc.fromDomain || parsed.fromDomain);

  dmarcBadge.textContent = verdict.toUpperCase();
  dmarcBadge.className = `status-pill ${cls}`;
  dmarcSummary.textContent = dmarc.reason || 'DMARC evaluation complete.';
  dmarcDetails.innerHTML = `
    ${row('Policy', dmarc.policy || '-')}
    ${dmarc.effectivePolicy ? row('Effective policy', dmarc.effectivePolicy) : ''}
    ${row('SPF aligned', dmarc.spfAligned ? 'Yes' : 'No')}
    ${row('DKIM aligned', dmarc.dkimAligned ? 'Yes' : 'No')}
    ${dmarc.dmarcRecord ? row('DMARC record', dmarc.dmarcRecord) : ''}
    ${alignmentNote}
  `;

  dmarcSection.classList.remove('hidden');
}

function row(key, val) {
  return `
    <div class="detail-row">
      <span class="detail-key">${key}</span>
      <span class="detail-val">${escHtml(String(val ?? '-'))}</span>
    </div>`;
}

function buildAlignmentNote(type, dmarc, parsed, authDomain) {
  if (!dmarc || !parsed) return '';

  const fromDomain = parsed.fromDomain || dmarc.fromDomain || '';
  const spfAligned = dmarc.spfAligned;
  const dkimAligned = dmarc.dkimAligned;
  const adkim = dmarc.adkim || 'r';
  const aspf = dmarc.aspf || 'r';

  if (type === 'dkim' && dkimAligned === false) {
    const auth = authDomain || 'unknown';
    const from = fromDomain || 'unknown';
    return alignmentNote(`DKIM alignment failed: ${auth} does not align with ${from} (${adkim} mode).`);
  }

  if (type === 'dmarc' && (spfAligned === false || dkimAligned === false)) {
    const spfLine = typeof spfAligned === 'boolean'
      ? `SPF ${spfAligned ? 'aligned' : 'not aligned'} (${aspf} mode)`
      : 'SPF alignment unknown';
    const dkimLine = typeof dkimAligned === 'boolean'
      ? `DKIM ${dkimAligned ? 'aligned' : 'not aligned'} (${adkim} mode)`
      : 'DKIM alignment unknown';
    return alignmentNote(`${spfLine}. ${dkimLine}.`);
  }

  return '';
}

function alignmentNote(text) {
  return `<div class="alignment-note">${escHtml(text)}</div>`;
}


// ══════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════
function resultToClass(r = '') {
  if (r === 'pass'     || r === 'deliver')    return 'pass';
  if (r === 'fail'     || r === 'reject')     return 'fail';
  if (r === 'softfail' || r === 'quarantine' || r === 'neutral' || r === 'temperror' || r === 'permerror') return 'warn';
  return 'none';
}

function getResultValue(result = {}) {
  return (result.result || result.verdict || result.action || result.status || 'none');
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
    btn.disabled     = false;
    btn.textContent  = btn.dataset.orig || btn.textContent;
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
  spoofWarning.classList.add('hidden');
  parsedFields.innerHTML = '';
  spfDetails.innerHTML = '';
  spfSummary.textContent = 'Run the analysis to see SPF results.';
  spfBadge.textContent = '-';
  spfBadge.className = 'status-pill';
  dkimDetails.innerHTML = '';
  dkimSummary.textContent = 'Run the analysis to see DKIM results.';
  dkimBadge.textContent = '-';
  dkimBadge.className = 'status-pill';
  dmarcDetails.innerHTML = '';
  dmarcSummary.textContent = 'Run the analysis to see DMARC results.';
  dmarcBadge.textContent = '-';
  dmarcBadge.className = 'status-pill';
  validationList.innerHTML = '';
  testcaseNote.classList.add('hidden');
  document.querySelectorAll('.demo-btn').forEach(b => b.classList.remove('active-case'));
}

// ── Init ───────────────────────────────────────────────────
loadTestCases();