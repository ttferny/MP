/**
 * ============================================================
 * script.js — Frontend Logic
 * Tiffany's deliverable.
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * This is the "brain" of the frontend page. It:
 *   1. Listens for user actions (button clicks, form submits)
 *   2. Sends the email header or domain to the backend API
 *   3. Reads the JSON response
 *   4. Updates the page to show the results clearly
 *
 * HOW IT CONNECTS TO THE BACKEND:
 * --------------------------------
 *   User clicks "Analyse Header"
 *     → POST /api/analyse/header  { rawHeader }
 *     → backend runs: parser.js → spf.js → dkim.js → dmarc.js
 *     → response: { parsed, results: { spf, dkim, dmarc } }
 *     → renderParsed()    shows extracted fields
 *     → renderPipeline()  shows SPF / DKIM / DMARC step results
 *     → renderVerdict()   shows final deliver/quarantine/reject
 *
 *   User clicks a Demo button
 *     → POST /api/analyse/scenario  { scenario }
 *     → same response shape — rendered the same way
 *
 *   User clicks "Lookup" (DNS tab)
 *     → POST /api/analyse/domain  { domain, dkimSelector }
 *     → response: { records: { spf, dkim, dmarc } }
 *     → renderDNS()  shows raw TXT records
 */

// ── Grab all DOM elements we need ─────────────────────────
const headerInput   = document.getElementById('header-input');
const analyseBtn    = document.getElementById('analyse-btn');
const clearBtn      = document.getElementById('clear-btn');
const inputError    = document.getElementById('input-error');

const parsedSection = document.getElementById('parsed-section');
const parsedFields  = document.getElementById('parsed-fields');

const pipelineSection = document.getElementById('pipeline-section');
const verdictBanner   = document.getElementById('verdict-banner');
const verdictIcon     = document.getElementById('verdict-icon');
const verdictLabel    = document.getElementById('verdict-label');
const verdictReason   = document.getElementById('verdict-reason');

const domainInput   = document.getElementById('domain-input');
const selectorInput = document.getElementById('selector-input');
const lookupBtn     = document.getElementById('lookup-btn');
const domainError   = document.getElementById('domain-error');
const dnsSection    = document.getElementById('dns-section');

// ── Tab switching ──────────────────────────────────────────
// When a tab button is clicked, show its panel and hide others.
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    // Update active button
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Show matching panel
    const target = btn.dataset.tab;
    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === `tab-${target}`);
    });
  });
});

// ── Demo scenario buttons ──────────────────────────────────
// Each button has a data-scenario attribute.
// Clicking it calls the /api/analyse/scenario endpoint and
// renders the result exactly like a real header analysis.
document.querySelectorAll('.demo-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const scenario = btn.dataset.scenario;
    setLoading(analyseBtn, true);
    hideError(inputError);
    clearResults();

    try {
      const res = await fetch('/api/analyse/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      const data = await res.json();

      if (!res.ok) {
        showError(inputError, data.error || 'Scenario failed.');
        return;
      }

      // Scenario response is nested under data.result
      const result = data.result;
      renderParsed(result.parsed);
      renderPipeline(result.results);
      renderVerdict(result.results.dmarc);

    } catch (err) {
      showError(inputError, `Network error: ${err.message}`);
    } finally {
      setLoading(analyseBtn, false);
    }
  });
});

// ── Analyse Header button ──────────────────────────────────
analyseBtn.addEventListener('click', analyseHeader);

// Also allow Enter key inside the textarea (Ctrl+Enter)
headerInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.ctrlKey) analyseHeader();
});

async function analyseHeader() {
  const rawHeader = headerInput.value.trim();

  hideError(inputError);
  clearResults();

  // Client-side check before hitting the server
  if (!rawHeader) {
    showError(inputError, 'Please paste an email header first.');
    return;
  }

  setLoading(analyseBtn, true);

  try {
    // POST to /api/analyse/header (routes/analyse.js → parser.js → spf.js → dkim.js → dmarc.js)
    const res = await fetch('/api/analyse/header', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawHeader }),
    });

    const data = await res.json();

    if (!res.ok) {
      // 400 = bad input, 422 = validation failed
      const msg = data.details
        ? `${data.error}: ${data.details.join(', ')}`
        : (data.error || 'Analysis failed.');
      showError(inputError, msg);
      return;
    }

    // Render all three sections
    renderParsed(data.parsed);
    renderPipeline(data.results);
    renderVerdict(data.results.dmarc);

  } catch (err) {
    showError(inputError, `Could not reach server: ${err.message}`);
  } finally {
    setLoading(analyseBtn, false);
  }
}

// ── Clear button ───────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  headerInput.value = '';
  hideError(inputError);
  clearResults();
});

// ─────────────────────────────────────────────────────────────
// RENDER: Parsed Header Fields
// Shows the key values extracted by parser.js in a grid.
// Highlights when fromDomain ≠ envelopeDomain (spoofing signal).
// ─────────────────────────────────────────────────────────────
function renderParsed(parsed) {
  parsedFields.innerHTML = '';

  // Fields to display and their friendly labels
  const fields = [
    { key: 'fromEmail',       label: 'From (visible sender)' },
    { key: 'fromDomain',      label: 'From Domain (DMARC checks this)' },
    { key: 'envelopeFrom',    label: 'Envelope From (Return-Path)' },
    { key: 'envelopeDomain',  label: 'Envelope Domain (SPF checks this)' },
    { key: 'senderIP',        label: 'Sender IP Address' },
    { key: 'subject',         label: 'Subject' },
    { key: 'date',            label: 'Date' },
    { key: 'messageId',       label: 'Message-ID' },
  ];

  // Show whether domains match — key spoofing signal
  const domainsMismatch = parsed.fromDomain &&
    parsed.envelopeDomain &&
    parsed.fromDomain !== parsed.envelopeDomain;

  for (const { key, label } of fields) {
    const val = parsed[key];
    const isEmpty = !val;

    // Highlight envelope domain in yellow if it differs from from domain
    const isMismatch = domainsMismatch &&
      (key === 'envelopeDomain' || key === 'envelopeFrom');

    const el = document.createElement('div');
    el.className = 'parsed-field';
    el.innerHTML = `
      <div class="parsed-field-key">${label}</div>
      <div class="parsed-field-value ${isMismatch ? 'mismatch' : ''} ${isEmpty ? 'empty' : ''}">
        ${isEmpty ? '(not found)' : escHtml(val)}
        ${isMismatch ? ' ⚠ differs from From domain' : ''}
      </div>
    `;
    parsedFields.appendChild(el);
  }

  // Show DKIM signature fields if present
  if (parsed.dkimSignature && Object.keys(parsed.dkimSignature).length > 0) {
    const sig = parsed.dkimSignature;
    const el = document.createElement('div');
    el.className = 'parsed-field';
    el.innerHTML = `
      <div class="parsed-field-key">DKIM Signature</div>
      <div class="parsed-field-value">
        domain: ${escHtml(sig.d || '—')} &nbsp;|&nbsp;
        selector: ${escHtml(sig.s || '—')} &nbsp;|&nbsp;
        algorithm: ${escHtml(sig.a || '—')}
      </div>
    `;
    parsedFields.appendChild(el);
  }

  parsedSection.classList.remove('hidden');
  pipelineSection.classList.remove('hidden');
}

// ─────────────────────────────────────────────────────────────
// RENDER: Authentication Pipeline
// Shows SPF → DKIM → DMARC steps with pass/fail badges.
// ─────────────────────────────────────────────────────────────
function renderPipeline(results) {
  renderStep('spf',  results.spf,  renderSPFDetails);
  renderStep('dkim', results.dkim, renderDKIMDetails);
  renderStep('dmarc',results.dmarc,renderDMARCDetails);
}

function renderStep(name, result, detailsFn) {
  const step    = document.getElementById(`step-${name}`);
  const badge   = document.getElementById(`${name}-badge`);
  const details = document.getElementById(`${name}-details`);

  // Determine the colour class from the result value
  const cls = resultToClass(result.result || result.verdict);
  step.className  = `pipeline-step ${cls}`;
  badge.className = `step-badge ${cls}`;
  badge.textContent = (result.result || result.verdict || '—').toUpperCase();

  // Fill in detail rows
  details.innerHTML = detailsFn(result);
}

function renderSPFDetails(spf) {
  return `
    ${detailRow('Domain checked', spf.domain || '—')}
    ${detailRow('Sender IP', spf.ip || '—')}
    ${spf.record ? detailRow('SPF Record', spf.record) : ''}
    ${spf.matchedMechanism ? detailRow('Matched rule', spf.matchedMechanism) : ''}
    <div class="detail-reason">${escHtml(spf.reason || '')}</div>
  `;
}

function renderDKIMDetails(dkim) {
  return `
    ${detailRow('Signing domain', dkim.domain || '—')}
    ${detailRow('Selector', dkim.selector || '—')}
    ${detailRow('Algorithm', dkim.algorithm || '—')}
    ${detailRow('DNS key found', dkim.dnsRecord ? 'Yes' : 'No')}
    <div class="detail-reason">${escHtml(dkim.reason || '')}</div>
  `;
}

function renderDMARCDetails(dmarc) {
  return `
    ${detailRow('Policy (p=)', dmarc.policy || '—')}
    ${detailRow('SPF aligned', dmarc.spfAligned ? '✅ Yes' : '❌ No')}
    ${detailRow('DKIM aligned', dmarc.dkimAligned ? '✅ Yes' : '❌ No')}
    ${dmarc.dmarcRecord ? detailRow('DMARC record', dmarc.dmarcRecord) : ''}
    <div class="detail-reason">${escHtml(dmarc.reason || '')}</div>
  `;
}

function detailRow(key, val) {
  return `
    <div class="detail-row">
      <span class="detail-key">${key}</span>
      <span class="detail-val">${escHtml(String(val))}</span>
    </div>
  `;
}

// ─────────────────────────────────────────────────────────────
// RENDER: Final Verdict Banner
// Shows the DMARC verdict prominently at the bottom.
// ─────────────────────────────────────────────────────────────
function renderVerdict(dmarc) {
  const verdict = dmarc.verdict || 'none';

  const config = {
    deliver:    { icon: '✅', label: 'DELIVER — Email is legitimate' },
    quarantine: { icon: '⚠️', label: 'QUARANTINE — Moved to spam' },
    reject:     { icon: '🚫', label: 'REJECT — Email blocked' },
    none:       { icon: '🔓', label: 'NO ACTION — No DMARC policy enforced' },
  };

  const { icon, label } = config[verdict] || config.none;

  verdictBanner.className = `verdict-banner ${verdict}`;
  verdictIcon.textContent  = icon;
  verdictLabel.textContent = label;
  verdictReason.textContent = dmarc.reason || '';
  verdictBanner.classList.remove('hidden');
}

// ─────────────────────────────────────────────────────────────
// DNS RECORD LOOKUP (Tab 2)
// Calls /api/analyse/domain and shows the raw TXT records.
// ─────────────────────────────────────────────────────────────
lookupBtn.addEventListener('click', lookupDomain);
domainInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') lookupDomain();
});

async function lookupDomain() {
  const domain   = domainInput.value.trim();
  const selector = selectorInput.value.trim() || 'default';

  hideError(domainError);
  dnsSection.classList.add('hidden');

  if (!domain) {
    showError(domainError, 'Please enter a domain name.');
    return;
  }

  setLoading(lookupBtn, true);

  try {
    const res = await fetch('/api/analyse/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, dkimSelector: selector }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(domainError, data.error || 'Lookup failed.');
      return;
    }

    renderDNS(data.domain, data.records, selector);

  } catch (err) {
    showError(domainError, `Could not reach server: ${err.message}`);
  } finally {
    setLoading(lookupBtn, false);
  }
}

function renderDNS(domain, records, selector) {
  // Update domain label in card title
  document.getElementById('dns-domain-label').textContent = domain;

  // SPF
  const spfFound = !!records.spf;
  document.getElementById('dns-spf-host').textContent   = domain;
  document.getElementById('dns-spf-badge').textContent  = spfFound ? 'Found' : 'Missing';
  document.getElementById('dns-spf-badge').className    = `dns-found-badge ${spfFound ? 'found' : 'missing'}`;
  document.getElementById('dns-spf-value').textContent  = records.spf || 'No SPF record found.';
  document.getElementById('dns-spf-explain').textContent = spfFound
    ? explainSPF(records.spf)
    : '⚠ No SPF record means anyone can send email claiming to be from this domain.';

  // DKIM
  const dkimFound = !!records.dkim;
  document.getElementById('dns-dkim-host').textContent  = `${selector}._domainkey.${domain}`;
  document.getElementById('dns-dkim-badge').textContent = dkimFound ? 'Found' : 'Missing';
  document.getElementById('dns-dkim-badge').className   = `dns-found-badge ${dkimFound ? 'found' : 'missing'}`;
  document.getElementById('dns-dkim-value').textContent = records.dkim || `No DKIM record found for selector "${selector}".`;

  // DMARC
  const dmarcFound = !!records.dmarc;
  document.getElementById('dns-dmarc-host').textContent   = `_dmarc.${domain}`;
  document.getElementById('dns-dmarc-badge').textContent  = dmarcFound ? 'Found' : 'Missing';
  document.getElementById('dns-dmarc-badge').className    = `dns-found-badge ${dmarcFound ? 'found' : 'missing'}`;
  document.getElementById('dns-dmarc-value').textContent  = records.dmarc || 'No DMARC record found.';
  document.getElementById('dns-dmarc-explain').textContent = dmarcFound
    ? explainDMARC(records.dmarc)
    : '⚠ No DMARC record means there is no policy to enforce — spoofed emails may be delivered.';

  dnsSection.classList.remove('hidden');
}

// Plain-English explanation of the SPF -all / ~all / ?all ending
function explainSPF(record) {
  if (!record) return '';
  if (record.includes('-all'))  return '"-all" → Strict: any IP not on the list should be rejected.';
  if (record.includes('~all'))  return '"~all" → Soft fail: unlisted IPs are suspicious but may be delivered.';
  if (record.includes('?all'))  return '"?all" → Neutral: no policy enforced for unlisted IPs.';
  if (record.includes('+all'))  return '"⚠ +all" → Passes everything — this is a dangerous misconfiguration.';
  return '';
}

// Plain-English explanation of the DMARC p= tag
function explainDMARC(record) {
  if (!record) return '';
  if (record.includes('p=reject'))     return '"p=reject" → Strongest protection: failed emails are blocked entirely.';
  if (record.includes('p=quarantine')) return '"p=quarantine" → Medium: failed emails go to spam.';
  if (record.includes('p=none'))       return '"p=none" → Monitoring only: no emails are blocked. Common misconfiguration.';
  return '';
}

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────

// Maps an SPF/DKIM/DMARC result string to a CSS class
function resultToClass(result) {
  if (!result) return 'none';
  const r = result.toLowerCase();
  if (r === 'pass' || r === 'deliver')    return 'pass';
  if (r === 'fail' || r === 'reject')     return 'fail';
  if (r === 'softfail' || r === 'quarantine') return 'warn';
  return 'none';
}

// Escapes HTML special characters to prevent XSS
// (never inject user data or server data directly as innerHTML without this)
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Shows a loading spinner inside a button and disables it
function setLoading(btn, loading) {
  if (loading) {
    btn.disabled = true;
    btn.dataset.originalText = btn.textContent;
    btn.innerHTML = '<span class="spinner"></span>Analysing…';
  } else {
    btn.disabled = false;
    btn.textContent = btn.dataset.originalText || btn.textContent;
  }
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideError(el) {
  el.textContent = '';
  el.classList.add('hidden');
}

// Hides all result sections and resets pipeline badges
function clearResults() {
  parsedSection.classList.add('hidden');
  pipelineSection.classList.add('hidden');
  verdictBanner.classList.add('hidden');
  parsedFields.innerHTML = '';

  ['spf', 'dkim', 'dmarc'].forEach(name => {
    const step  = document.getElementById(`step-${name}`);
    const badge = document.getElementById(`${name}-badge`);
    const det   = document.getElementById(`${name}-details`);
    if (step)  step.className  = 'pipeline-step';
    if (badge) { badge.className = 'step-badge'; badge.textContent = '—'; }
    if (det)   det.innerHTML   = '';
  });
}