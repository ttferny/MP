/**
 * spf.js — SPF POC / Live Auditor Logic
 *
 * WHAT THIS DOES:
 * ---------------
 * 1. Checks for ?domain= parameters on page load and automatically evaluates.
 * 2. Connects to the dynamic backend endpoint /api/spf/check.
 * 3. Injects a custom 10 DNS Lookup Speedometer with real-time flashing red error indicators.
 * 4. Renders an interactive waterfall evaluation mechanism trace timeline.
 * 5. Adds tooltip popovers to all labelled data fields explaining what each value means.
 *
 * PITCH NOTE:
 * The UI speaks in two registers: plain-English business value for non-technical
 * stakeholders, and trace-level detail for technical review.
 */

// ── DOM Element Selectors ───────────────────────────────────
const domainInput       = document.getElementById('domain-input');
const ipInput           = document.getElementById('ip-input');
const recordInput       = document.getElementById('record-input');
const aInput            = document.getElementById('a-input');
const mxInput           = document.getElementById('mx-input');
const includeInput      = document.getElementById('include-input');
const emailFileInput    = document.getElementById('email-file-input');
const uploadStatus      = document.getElementById('upload-status');
const evaluateBtn       = document.getElementById('evaluate-btn');
const resetBtn          = document.getElementById('reset-btn');

const resultBadge            = document.getElementById('result-badge');
const resultSummary          = document.getElementById('result-summary');
const traceList              = document.getElementById('trace-list');
const policySummaryText      = document.getElementById('policy-summary-text');
const commercialStatus       = document.getElementById('commercial-status');
const commercialRisk         = document.getElementById('commercial-risk');
const commercialRecommendation = document.getElementById('commercial-recommendation');
const commercialImpact       = document.getElementById('commercial-impact');
const commercialHighlights   = document.getElementById('commercial-highlights');
const dnsStatusBadge         = document.getElementById('dns-status-badge');
const spfStatusBadge         = document.getElementById('spf-status-badge');

const scenarioGrid = document.getElementById('scenario-grid');
const scenarioNote = document.getElementById('scenario-note');

const accordionTriggers = document.querySelectorAll('.accordion-trigger');

accordionTriggers.forEach((trigger) => {
  const panelId = trigger.dataset.target;
  const panel = document.getElementById(panelId);
  const item = trigger.closest('.accordion-item');

  if (!panel || !item) return;

  trigger.addEventListener('click', () => {
    panel.classList.toggle('hidden');
    item.classList.toggle('open');
  });
});

// ── Small HTML escape helper ─────────────────────────────────
function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Tooltip Definitions ──────────────────────────────────────
// Plain-language explanation of each field shown on the page.
// Each entry maps an element ID (or semantic key) → { title, body }.
// The tooltip copy is intended to let a presenter switch between business
// explanation and protocol detail without changing screens.
const TOOLTIPS = {
  'domain-input': {
    title: 'Domain',
    body: 'The domain being tested — this is the owner of the email policy. SPF checks whether the sending server is authorised to send mail on behalf of this domain.',
  },
  'ip-input': {
    title: 'Sender IP',
    body: 'The IPv4 address that actually sent the message. SPF compares this IP against the list of approved servers published by the domain.',
  },
  'record-input': {
    title: 'SPF Record',
    body: 'The raw DNS TXT policy string published by the domain. It lists which servers are allowed to send email on its behalf (e.g. ip4:, include:, -all).',
  },
  'a-input': {
    title: 'Resolved A Records',
    body: 'The IP addresses that the domain\'s hostname resolves to. Used when an SPF record contains an "a" mechanism — it passes if the sender IP matches one of these.',
  },
  'mx-input': {
    title: 'Resolved MX Records',
    body: 'The mail exchange servers for the domain. Used when an SPF record contains an "mx" mechanism — it passes if the sender IP matches one of these hosts.',
  },
  'include-input': {
    title: 'Include Records',
    body: 'Shows the chain of other domains whose SPF records were also checked. Each "include:" in the record pulls in another domain\'s policy. More includes = more DNS lookups (limit: 10).',
  },
  'result-badge': {
    title: 'SPF Result',
    body: 'The final verdict. PASS = authorised sender. FAIL = not authorised, likely rejected. SOFTFAIL = suspicious, delivered with a warning. NEUTRAL / NONE = no clear policy published.',
  },
  'trace-list': {
    title: 'Evaluation Trace',
    body: 'Step-by-step walkthrough of how SPF evaluated each mechanism in the record. Mechanisms are checked in order — the first one that matches decides the result.',
  },
  'commercial-status': {
    title: 'Business Status',
    body: 'A plain-English translation of the technical result — e.g. "Authorised Sender" or "Spoofing Risk". Useful for communicating the outcome to non-technical stakeholders.',
  },
  'commercial-risk': {
    title: 'Risk Score',
    body: 'A 0–100 score summarising exposure. Higher means greater risk of spoofing or deliverability issues. Based on the SPF result, policy strength, and DNS lookup count.',
  },
  'commercial-recommendation': {
    title: 'Recommendation',
    body: 'What you should do with this email based on the result — e.g. "Safe to proceed" or "Verify the sender through a trusted channel before clicking links or acting on requests".',
  },
  'commercial-impact': {
    title: 'Business Impact',
    body: 'What trusting this email could mean for you — e.g. whether it is very unlikely to be a spoof or whether acting on it risks engaging with a phishing or impersonation attempt.',
  },
  'commercial-highlights': {
    title: 'SPF Policy Analysis',
    body: 'A plain-language breakdown of what the domain\'s SPF record actually does — which senders are trusted, what enforcement level is set, whether there are any configuration concerns, and the specific SPF and DNS findings that support the recommendation.',
  },
  'speedo-count': {
    title: 'DNS Lookup Count',
    body: 'SPF evaluation is limited to 10 DNS lookups per RFC 7208. Each "include:", "a", "mx", or "redirect" costs one lookup. Exceeding 10 causes a PermError — even legitimate mail may be rejected.',
  }
};

// ── Tooltip DOM Injection ────────────────────────────────────
// Injects a lightweight CSS-based tooltip onto any labelled element.
// Finds the <label> ancestor of each input and appends a "?" icon.
function applyTooltips() {
  // Inject tooltip styles once
  if (document.getElementById('spf-tooltip-styles')) return;
  const tooltipStyle = document.createElement('style');
  tooltipStyle.id = 'spf-tooltip-styles';
  tooltipStyle.textContent = `
    .spf-tooltip-wrap {
      position: relative;
      display: inline-flex;
      align-items: center;
    }
    .spf-tooltip-icon {
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
    .spf-tooltip-icon.small-icon {
      width: 16px;
      height: 16px;
      font-size: 0.68rem;
      text-transform: lowercase;
      
    }
    
    .spf-tooltip-bubble {
      display: none;
      position: absolute;
      left: 0;
      top: calc(100% + 6px);
      z-index: 9999;
      width: 260px;
      background: var(--ink);
      color: #f3efe8;
      /* Prevent inherited uppercase/letter-spacing from parent titles */
      text-transform: none !important;
      letter-spacing: normal !important;
      /* Prevent inherited bold weight from parent titles */
      font-weight: 400 !important;
      border-radius: 10px;
      padding: 10px 13px;
      font-size: 0.78rem;
      line-height: 1.5;
      font-family: 'Sora', sans-serif;
      pointer-events: none;
      box-shadow: 0 8px 24px rgba(0,0,0,0.22);
    }
    .spf-tooltip-bubble::before {
      content: '';
      position: absolute;
      top: -5px;
      left: 14px;
      width: 10px;
      height: 10px;
      background: var(--ink);
      transform: rotate(45deg);
      border-radius: 2px;
    }
    .spf-tooltip-bubble .tip-title {
      font-weight: 700;
      font-size: 0.8rem;
      margin-bottom: 4px;
      color: #fff;
    }
    .spf-tooltip-icon:hover + .spf-tooltip-bubble,
    .spf-tooltip-icon:focus + .spf-tooltip-bubble {
      display: block;
    }
    /* Keep tooltip visible when hovering inside it */
    .spf-tooltip-wrap:hover .spf-tooltip-bubble {
      display: block;
    }
  `;
  document.head.appendChild(tooltipStyle);

  // Attach tooltip to each element that has a definition
// ── Scenarios Dataset ────────────────────────────────────────
// Prebuilt scenarios make the feature easy to demo while still showing
// realistic SPF policy outcomes and edge cases.
  Object.entries(TOOLTIPS).forEach(([id, tip]) => {
    const el = document.getElementById(id);
    if (!el) return;

    // Find the label ancestor (for inputs/textareas) or the element's parent card title
    const labelEl = el.closest('label');
    if (labelEl) {
      attachTooltipToLabel(labelEl, tip);
    } else {
      // For non-label targets (badge, trace, commercial items), attach to the nearest
      // .commercial-label sibling or the card-title
      const cardItem = el.closest('.commercial-item');
      if (cardItem) {
        const labelSpan = cardItem.querySelector('.commercial-label');
        if (labelSpan) attachTooltipInline(labelSpan, tip);
      } else {
        // result-badge, trace-list, policy-summary-text — attach to the card title above them
        const card = el.closest('.card');
        if (card) {
          const cardTitle = card.querySelector('.card-title');
          if (cardTitle) attachTooltipInline(cardTitle, tip);
        }
      }
    }
  });
}

// Wrap the text content of a <label> so the "?" icon sits beside the label text
function attachTooltipToLabel(labelEl, tip) {
  // Don't double-attach
  if (labelEl.querySelector('.spf-tooltip-icon')) return;

  // Grab the first text node (the label text itself)
  const firstText = [...labelEl.childNodes].find(n => n.nodeType === Node.TEXT_NODE && n.textContent.trim());
  if (!firstText) return;

  const wrap = document.createElement('span');
  wrap.className = 'spf-tooltip-wrap';
  wrap.style.display = 'inline-flex';
  wrap.style.alignItems = 'center';

  const textSpan = document.createElement('span');
  textSpan.textContent = firstText.textContent;

  const icon = buildTooltipIcon(tip);
  wrap.appendChild(textSpan);
  wrap.appendChild(icon.icon);
  wrap.appendChild(icon.bubble);

  firstText.replaceWith(wrap);
}

// Append "?" icon directly after an inline element (card title, commercial label, etc.)
function attachTooltipInline(el, tip) {
  if (el.querySelector('.spf-tooltip-icon')) return;

  const wrap = document.createElement('span');
  wrap.className = 'spf-tooltip-wrap';
  wrap.style.display = 'inline-flex';
  wrap.style.alignItems = 'center';
  wrap.style.gap = '4px';

  // Move existing text into wrap
  const clone = el.cloneNode(true);
  // Replace el content with wrap containing clone's inner content + icon
  const textSpan = document.createElement('span');
  textSpan.innerHTML = el.innerHTML;

  const icon = buildTooltipIcon(tip);
  
  // Add small-icon class for commercial labels (Status, Risk Score, Recommendation, Business Impact)
  if (el.classList.contains('commercial-label')) {
    icon.icon.classList.add('small-icon');
  }

  wrap.appendChild(textSpan);
  wrap.appendChild(icon.icon);
  wrap.appendChild(icon.bubble);

  el.innerHTML = '';
  el.appendChild(wrap);
}

function buildTooltipIcon(tip) {
  const icon = document.createElement('span');
  icon.className = 'spf-tooltip-icon';
  icon.setAttribute('aria-label', `What is ${tip.title}?`);
  icon.setAttribute('role', 'tooltip');
  icon.setAttribute('tabindex', '0');
  icon.textContent = 'i';

  const bubble = document.createElement('div');
  bubble.className = 'spf-tooltip-bubble';
  bubble.innerHTML = `<div class="tip-title">${escapeHtml(tip.title)}</div>${escapeHtml(tip.body)}`;

  return { icon, bubble };
}

// ── Speedometer styles (injected once) ──────────────────────
const style = document.createElement('style');
style.textContent = `
  @keyframes speedo-pulse {
    0%   { background-color: #b91c1c; box-shadow: 0 0 4px #b91c1c; }
    50%  { background-color: #ef4444; box-shadow: 0 0 12px #ef4444; }
    100% { background-color: #b91c1c; box-shadow: 0 0 4px #b91c1c; }
  }
  .speedo-flash-red {
    animation: speedo-pulse 0.8s infinite ease-in-out !important;
  }
`;
document.head.appendChild(style);

// ── Dynamic Speedometer Component ───────────────────────────
function injectSpeedometerDOM() {
  const resultCard = document.querySelector('.result-card');
  if (!resultCard) return;
  if (document.getElementById('spf-speedometer')) return;

  const speedoWrapper = document.createElement('div');
  speedoWrapper.id = 'spf-speedometer';
  speedoWrapper.style.cssText = 'margin: 16px 0; padding: 12px; background: var(--bg-strong); border: 1px solid var(--border); border-radius: 12px;';

  speedoWrapper.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; margin-bottom: 6px;">
      <span id="speedo-label-wrap" style="color: var(--muted); font-weight: 600;">10 DNS Lookup Speedometer</span>
      <span id="speedo-count" style="font-weight: 700; color: var(--ink);">0 / 10</span>
    </div>
    <div style="background: var(--border); height: 10px; border-radius: 999px; overflow: hidden; position: relative; width: 100%;">
      <div id="speedo-fill" style="height: 100%; width: 0%; background: var(--success); transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1), background-color 0.3s ease;"></div>
    </div>
    <div id="speedo-alert" style="display: none; margin-top: 10px; padding: 8px 12px; background: rgba(185,28,28,0.08); border: 1px solid rgba(185,28,28,0.3); color: var(--danger); border-radius: 8px; font-size: 0.78rem; font-weight: 600; text-align: center; font-family: 'JetBrains Mono', monospace;">
      ⚠️ SPF PermError: Too many DNS lookups
    </div>
  `;

  resultCard.insertBefore(speedoWrapper, traceList);

  // Attach tooltip to the speedometer label after injecting into DOM
  const labelEl = document.getElementById('speedo-label-wrap');
  const countEl = document.getElementById('speedo-count');
  if (labelEl && TOOLTIPS['speedo-count']) {
    attachTooltipInline(labelEl, TOOLTIPS['speedo-count']);
  }
}

function updateSpeedometer(lookups) {
  injectSpeedometerDOM();

  const countEl  = document.getElementById('speedo-count');
  const fillEl   = document.getElementById('speedo-fill');
  const alertEl  = document.getElementById('speedo-alert');
  if (!countEl || !fillEl || !alertEl) return;

  const count = parseInt(lookups) || 0;
  countEl.textContent = `${count} / 10`;

  const percentage = Math.min(100, (count / 10) * 100);
  fillEl.style.width = `${percentage}%`;

  if (count > 10) {
    fillEl.style.backgroundColor = '#b91c1c';
    fillEl.classList.add('speedo-flash-red');
    alertEl.style.display = 'block';
    countEl.style.color = 'var(--danger)';
  } else {
    fillEl.style.backgroundColor = 'var(--success)';
    fillEl.classList.remove('speedo-flash-red');
    alertEl.style.display = 'none';
    countEl.style.color = 'var(--ink)';
  }
}

// ── Scenarios Dataset ────────────────────────────────────────
const scenarios = [
  {
    key: 'google',
    title: 'Major Provider',
    note: 'Live DNS example. Result depends on the chosen IP.',
    data: { domain: 'google.com', ip: '64.233.160.0' }
  },
  {
    key: 'strict',
    title: 'Strict -all Policy',
    note: 'Domains like example.com publish -all for testing.',
    data: { domain: 'example.com', ip: '203.0.113.55' }
  },
  {
    key: 'marketing',
    title: 'Marketing Sender',
    note: 'Try an ESP domain to see include chains.',
    data: { domain: 'sendgrid.net', ip: '167.89.0.0' }
  },
  {
    key: 'custom',
    title: 'Your Own Domain',
    note: 'Replace with any domain you want to test.',
    data: { domain: 'example.org', ip: '203.0.113.99' }
  }
];

// Render the "Quick Scenarios" preset buttons and wire each to auto-run on click.
function loadScenarios() {
  if (!scenarioGrid) return;
  scenarioGrid.innerHTML = '';
  scenarios.forEach((scenario) => {
    const card = document.createElement('button');
    card.className = 'scenario-card';
    card.type = 'button';
    card.innerHTML = `<strong>${scenario.title}</strong><span>${scenario.note}</span>`;

    card.addEventListener('click', () => {
      document.querySelectorAll('.scenario-card').forEach((el) => el.classList.remove('active'));
      card.classList.add('active');
      applyScenario(scenario);
    });

    scenarioGrid.appendChild(card);
  });
}

// Load a preset's domain + IP into the inputs and immediately evaluate it.
function applyScenario(scenario) {
  const { domain, ip } = scenario.data;
  if (domainInput) domainInput.value = domain;
  if (ipInput) ipInput.value = ip;
  if (scenarioNote) scenarioNote.textContent = scenario.note;
  evaluateSpf();
}

// Work out where the backend lives: an explicitly configured base wins, else the
// page's own origin (when served over http/https), else localhost for dev.
function getApiBaseUrl() {
  const configuredBase = document.body?.dataset?.apiBaseUrl;
  if (configuredBase) return configuredBase.replace(/\/$/, '');
  if (window.location.protocol === 'http:' || window.location.protocol === 'https:') return window.location.origin;
  return 'http://localhost:3000';
}

// Build an ordered list of backend URLs to try — primary first, then localhost as
// a fallback — so the demo still works whether opened from a server or a file.
function getApiTargets() {
  const targets = [];
  const apiBaseUrl = getApiBaseUrl();
  if (apiBaseUrl) targets.push(apiBaseUrl);
  const localhost = 'http://localhost:3000';
  if (!targets.includes(localhost)) targets.push(localhost);
  return targets;
}

// Call POST /api/spf/check, trying each candidate backend until one responds.
// Returns the parsed JSON verdict, or throws the last error if all targets fail.
async function fetchSpfEvaluation(domain, ip) {
  const payload = JSON.stringify({ domain, ip });
  console.debug('[SPF POC] Sending payload to /api/spf/check:', { domain, ip });
  let lastError = null;

  for (const apiBaseUrl of getApiTargets()) {
    try {
      const response = await fetch(`${apiBaseUrl}/api/spf/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
      });

      const data = await response.json();
      console.debug('[SPF POC] Received response from', apiBaseUrl, data);

      if (!response.ok) {
        const error = new Error(data?.error || 'SPF lookup validation failed.');
        error.responseData = data;
        throw error;
      }

      return data;
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError || new Error('Unable to reach SPF backend.');
}

// ── Core Evaluation Logic ────────────────────────────────────
// The flow below mirrors how an actual mail server reasons about SPF, but the
// output is arranged so a presenter can explain each stage in sequence.
async function evaluateSpf() {
  const domain = domainInput?.value.trim();
  const ip     = ipInput?.value.trim();

  if (traceList)    traceList.innerHTML = '';
  if (recordInput)  recordInput.value = '';
  if (aInput)       aInput.value = '';
  if (mxInput)      mxInput.value = '';
  if (includeInput) includeInput.value = '';
  if (dnsStatusBadge) dnsStatusBadge.textContent = 'LIVE';
  updateSpeedometer(0);

  if (!domain || !ip) {
    setResult('neutral', 'Enter a domain and sender IP to evaluate.');
    return;
  }

  setLoading(true);

  try {
    const data = await fetchSpfEvaluation(domain, ip);

    if (recordInput) recordInput.value = data.record || '(no SPF record found)';
    if (aInput) aInput.value = (data.dns?.aRecords || []).join(', ') || '(none)';

    const mxRecords = data.dns?.mxRecords || [];
    if (mxInput) {
      mxInput.value = mxRecords.length
        ? mxRecords.map((mx) => (typeof mx === 'string' ? mx : `${mx.exchange} (${mx.priority})`)).join(', ')
        : '(none)';
    }

    const includeEntries = Object.entries(data.includeRecords || {});
    if (includeInput) {
      includeInput.value = includeEntries.length
        ? includeEntries.map(([key, value]) => `${key} = ${value}`).join('\n')
        : '(none)';
    }

    if (dnsStatusBadge) {
      dnsStatusBadge.textContent = 'LIVE';
      dnsStatusBadge.classList.remove('pass', 'fail', 'warn');
      dnsStatusBadge.classList.add('pass');
    }

    const totalLookups = data.lookupCount ?? data.dnsLookups ?? data.lookups ?? 0;
    updateSpeedometer(totalLookups);

    setResult(mapResultClass(data.result || 'neutral'), data.reason || 'SPF evaluation complete.');
    renderTrace(data.trace || [], data.result);
    renderPolicySummary(data);
    renderCommercial(data.commercial || null);

  } catch (err) {
    console.error('SPF Evaluation Error:', err);
    
    // Determine error type for better user messaging
    let errorMessage = 'Unable to complete SPF evaluation.';
    let errorDetail = '';
    
    if (err.message?.includes('fetch') || err.message?.includes('network') || err.name === 'TypeError') {
      errorMessage = 'Network Connection Error';
      errorDetail = 'Could not reach the SPF evaluation server. Please check your internet connection and try again.';
    } else if (err.message?.includes('timeout')) {
      errorMessage = 'Request Timeout';
      errorDetail = 'The server took too long to respond. Please try again.';
    } else if (err.responseData?.error) {
      errorMessage = 'SPF Validation Error';
      errorDetail = err.responseData.error;
    } else {
      errorMessage = 'Unexpected Error';
      errorDetail = err.message || 'An unknown error occurred during SPF evaluation.';
    }
    
    setResult('fail', errorMessage);
    if (traceList) {
      traceList.innerHTML = `
        <div class="trace-row" style="border-color: var(--danger); background: rgba(185,28,28,0.05);">
          <strong style="color: var(--danger);">⚠️ ${errorMessage}</strong>
          <span style="color: var(--muted); font-size: 0.85rem; margin-top: 4px;">${errorDetail}</span>
        </div>`;
    }
    
    // Clear commercial summary on error
    if (commercialStatus) commercialStatus.textContent = 'Error';
    if (commercialRisk) commercialRisk.textContent = '—';
    if (commercialRecommendation) commercialRecommendation.textContent = 'Please try again.';
    if (commercialImpact) commercialImpact.textContent = '—';
    
    // Update DNS status badge
    if (dnsStatusBadge) {
      dnsStatusBadge.textContent = 'ERROR';
      dnsStatusBadge.classList.remove('pass', 'warn');
      dnsStatusBadge.classList.add('fail');
    }
  } finally {
    setLoading(false);
  }
}

// ── Waterfall Trace Builder ──────────────────────────────────
// Renders the step-by-step evaluation timeline. Short traces (≤5 steps) show in
// full; longer ones collapse the middle so a presenter can focus on start + end.
function renderTrace(steps, finalResult) {
  if (!traceList) return;
  traceList.innerHTML = '';

  if (!steps || !steps.length) {
    traceList.innerHTML = '<div class="trace-row"><strong>No trace returned</strong><span>The backend did not return a mechanism path for this domain and IP.</span></div>';
    return;
  }

  const total = steps.length;

  function makeRow(step, index, isFinal) {
    const row = document.createElement('div');
    row.className = 'trace-row';
    row.style.cssText = 'display: flex; flex-direction: column; position: relative; padding-left: 16px; margin-bottom: 8px; border-left: 3px solid var(--border);';

    const stepTitle  = isFinal
      ? `Step ${index + 1}: Path Match Finalized!`
      : `Step ${index + 1}: Checking ${step.mechanism || 'Mechanism'}`;
    const outcomeText = step.detail || 'Evaluating criteria path rule.';

    row.style.borderLeftColor = isFinal ? 'var(--success)' : 'rgba(16,122,127,0.12)';

    row.innerHTML = `
      <div class="trace-row-head">
        <strong class="trace-title">${escapeHtml(stepTitle)}</strong>
        <button class="trace-toggle-details" aria-expanded="false">Details</button>
      </div>
      <div class="trace-row-body" style="display:none; margin-top:6px;">
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--muted);">
          ${step.mechanism ? `<code>${escapeHtml(step.mechanism)}</code> → ` : ''}${escapeHtml(outcomeText)} [${escapeHtml(step.outcome || 'Processed')}]
        </div>
      </div>
    `;

    const toggle = row.querySelector('.trace-toggle-details');
    const body   = row.querySelector('.trace-row-body');
    toggle.addEventListener('click', () => {
      const expanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!expanded));
      body.style.display = expanded ? 'none' : 'block';
      toggle.textContent = expanded ? 'Details' : 'Hide';
    });

    return row;
  }

  // If there are 5 or fewer steps, render them all in order
  if (total <= 5) {
    steps.forEach((s, i) => traceList.appendChild(makeRow(s, i, i === total - 1)));
    return;
  }

  // For longer traces (>5): show first 2 and last 2 with a collapsed button
  const first = steps.slice(0, 2);
  const last  = steps.slice(total - 2, total);

  first.forEach((s, i) => traceList.appendChild(makeRow(s, i, false)));

  const remainingCount = total - 4;
  const collapsed = document.createElement('div');
  collapsed.className = 'trace-collapsed';
  collapsed.style.cssText = 'padding: 8px 12px; margin-bottom:8px; color: var(--muted); background: rgba(243, 239, 232, 0.95); border-radius: 8px;';
  collapsed.innerHTML = `<button class="btn-secondary" id="show-full-trace" aria-expanded="false">Show ${remainingCount} more steps</button>`;
  traceList.appendChild(collapsed);

  // Append the last two steps (final step marked accordingly) and keep a reference
  let firstLastNode = null;
  last.forEach((s, idx) => {
    const globalIndex = total - 2 + idx;
    const isFinal = (globalIndex === total - 1);
    const node = makeRow(s, globalIndex, isFinal);
    if (!firstLastNode) firstLastNode = node;
    traceList.appendChild(node);
  });

  // Toggle behavior: insert/remove middle steps when button pressed
  const toggleBtn = collapsed.querySelector('#show-full-trace');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
      if (expanded) {
        // Collapse: remove middle nodes
        const middles = traceList.querySelectorAll('.trace-middle');
        middles.forEach(n => n.remove());
        toggleBtn.setAttribute('aria-expanded', 'false');
        toggleBtn.textContent = `Show ${remainingCount} more steps`;
      } else {
        // Expand: insert middle nodes before the first of the last nodes
        const middle = steps.slice(2, total - 2);
        const frag = document.createDocumentFragment();
        middle.forEach((s, idx) => {
          const n = makeRow(s, 2 + idx, false);
          n.classList.add('trace-middle');
          frag.appendChild(n);
        });
        if (firstLastNode) traceList.insertBefore(frag, firstLastNode);
        else traceList.appendChild(frag);
        toggleBtn.setAttribute('aria-expanded', 'true');
        toggleBtn.textContent = `Hide ${remainingCount} steps`;
      }
    });

    // Keyboard: allow Enter/Space to toggle when focused
    toggleBtn.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        toggleBtn.click();
      }
    });
  }
}

// ── Helper Controllers ───────────────────────────────────────
// Collapse the seven RFC result strings into the four the UI styles/animates
// (pass/fail/softfail/neutral) — none/permerror/temperror all render as neutral.
function mapResultClass(result) {
  const normalized = String(result || '').toLowerCase();
  if (['pass', 'fail', 'softfail', 'neutral'].includes(normalized)) return normalized;
  if (['none', 'permerror', 'temperror'].includes(normalized)) return 'neutral';
  return 'neutral';
}

// Update the big result badge + summary line (and the small status pill).
function setResult(result, summary) {
  if (!resultBadge || !resultSummary) return;
  resultBadge.className = `result-badge ${result}`;
  resultBadge.textContent = String(result || '').toUpperCase() || 'NEUTRAL';
  resultSummary.textContent = summary;
  if (spfStatusBadge) {
    spfStatusBadge.classList.remove('pass', 'fail', 'warn', 'neutral');
    spfStatusBadge.classList.add(result || 'neutral');
    spfStatusBadge.textContent = String(result || 'NEUTRAL').toUpperCase() || 'NEUTRAL';
  }
}

// Handle an uploaded .eml/.txt: read it, auto-extract the sender domain + IP,
// and pre-fill the form — lets users audit a real message they received.
function handleEmailFileUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) {
    if (uploadStatus) uploadStatus.textContent = 'No file selected.';
    return;
  }

  const maxSizeBytes = 1024 * 1024;
  if (file.size > maxSizeBytes) {
    if (uploadStatus) uploadStatus.textContent = 'File is too large. Please upload a file under 1MB.';
    event.target.value = '';
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || '');
    const parsed = extractEmailFields(text);

    if (parsed.domain && domainInput) {
      domainInput.value = parsed.domain;
    }

    if (parsed.ip && ipInput) {
      ipInput.value = parsed.ip;
    }

    if (uploadStatus) {
      const parts = [];
      if (parsed.domain) parts.push(`domain: ${parsed.domain}`);
      if (parsed.ip) parts.push(`ip: ${parsed.ip}`);
      uploadStatus.textContent = parts.length
        ? `Loaded ${file.name} (${parts.join(', ')})`
        : `Loaded ${file.name}, but no sender IP or domain could be extracted.`;
    }
  };

  reader.onerror = () => {
    if (uploadStatus) uploadStatus.textContent = 'Could not read the file. Please try another file.';
    event.target.value = '';
  };

  reader.readAsText(file);
}

// Pull the sender domain and originating IP out of raw email header text.
function extractEmailFields(text) {
  const headers = String(text || '').replace(/\r/g, '');
  return {
    domain: extractSenderDomain(headers),
    ip: extractSenderIp(headers),
  };
}

// Try several common header patterns to find the true originating sender IP.
function extractSenderIp(headers) {
  const patterns = [
    /client-ip=([0-9a-fA-F:.]+)/i,
    /X-Originating-IP:\s*\[?([0-9a-fA-F:.]+)\]?/i,
    /Received-SPF:[^\n]*client-ip=([0-9a-fA-F:.]+)/i,
    /Received:\s*from[^\n]*\[((?:\d{1,3}\.){3}\d{1,3})\]/i,
    /Received:\s*from\s+[^\n]*\s+\[((?:\d{1,3}\.){3}\d{1,3})\]/i,
  ];

  for (const pattern of patterns) {
    const match = headers.match(pattern);
    if (match) return match[1];
  }

  return '';
}

// Try several common header patterns to find the sender's domain (the SPF owner).
function extractSenderDomain(headers) {
  const patterns = [
    /header\.from=([^;\s]+)/i,
    /smtp\.mailfrom="?([^";>\s]+)"?/i,
    /Return-Path:\s*<[^>]*@([^>\s]+)>/i,
    /From:\s*(?:.*<)?[^@\s<>]+@([^>\s]+)>?/i,
    /Authentication-Results:[^\n]*header\.from=([^;\s]+)/i,
  ];

  for (const pattern of patterns) {
    const match = headers.match(pattern);
    if (match) {
      const value = match[1].trim().replace(/[<>"']/g, '');
      if (value.includes('@')) return value.split('@').pop();
      return value;
    }
  }

  return '';
}

// Paint the business-facing panel (status, risk score, recommendation, impact,
// highlights) from the backend's `commercial` object — the stakeholder view.
function renderCommercial(summary) {
  if (!commercialStatus || !commercialRisk || !commercialRecommendation || !commercialImpact || !commercialHighlights) return;

  if (!summary) {
    commercialStatus.textContent = 'Awaiting evaluation';
    commercialRisk.textContent = '—';
    commercialRecommendation.textContent = 'Run the auditor to see guidance.';
    commercialImpact.textContent = '—';
    commercialHighlights.innerHTML = '';
    return;
  }

  commercialStatus.textContent        = summary.status || 'Unknown';
  commercialRisk.textContent          = summary.riskScore != null ? `${summary.riskScore}%` : 'N/A';

  
  commercialRecommendation.textContent =
    summary.recommendation || 'Verify the sender through a trusted channel before acting on this email.';

    commercialImpact.textContent        = summary.businessImpact || 'The sender\'s authenticity could not be confirmed, so this email should be treated with caution.';

  if (Array.isArray(summary.highlights) && summary.highlights.length) {
    commercialHighlights.innerHTML = `<ul>${summary.highlights.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
  } else {
    commercialHighlights.innerHTML = '<p style="color: var(--muted); margin: 0;">No highlight details available.</p>';
  }
}

// Derive a plain-English policy read-out from the raw record: enforcement level,
// how many IPs/includes it trusts, and a recommendation on how to strengthen it.
function renderPolicySummary(data) {
  if (!policySummaryText) return;
  const record         = String(data.record || '');
  const includeRecords = data.includeRecords || {};
  const includes       = Array.isArray(includeRecords) ? includeRecords : Object.keys(includeRecords || {});
  const ip4s           = (record.match(/ip4:[^\s]+/g) || []).map((t) => t.replace('ip4:', ''));
  const redirects      = (record.match(/redirect=[^\s]+/g) || []).map((t) => t.replace('redirect=', ''));
  const matched        = data.matchedMechanism || null;
  const lookups        = Number(data.lookupCount || data.dnsLookups || 0);

  if (!record) {
    policySummaryText.innerHTML = `<strong>No SPF record found</strong><div style="color:var(--muted); margin-top:6px;">This domain has no SPF TXT record — publish a policy to prevent unauthorized senders.</div>`;
    return;
  }

  let enforcement = 'No explicit enforcement';
  if (/\-all\b/.test(record))  enforcement = 'Strict enforcement (-all)';
  else if (/~all\b/.test(record)) enforcement = 'Soft enforcement (~all) — monitoring';
  else if (/\?all\b/.test(record)) enforcement = 'Neutral (?all) — no claim';
  else if (/\+all\b/.test(record)) enforcement = 'Permissive (+all) — allows any sender';

  const highlights = [];
  highlights.push(enforcement);
  if (matched)          highlights.push(`Matched mechanism: ${matched}`);
  if (ip4s.length)      highlights.push(`${ip4s.length} direct IP${ip4s.length > 1 ? 's' : ''}`);
  if (includes.length)  highlights.push(`${includes.length} include/redirect domain${includes.length > 1 ? 's' : ''}`);
  if (redirects.length) highlights.push(`Redirects to ${redirects.join(', ')}`);
  if (lookups > 10)     highlights.push(`High DNS lookup count: ${lookups} (may cause PermError)`);

  let recommendation = 'No immediate action required.';
  if (/\-all\b/.test(record))  recommendation = 'Policy is enforcing; monitor and maintain known senders.';
  else if (/~all\b/.test(record)) recommendation = 'Consider moving to -all after validating all legitimate senders.';
  else if (!record)             recommendation = 'Publish an SPF record to state authorized senders.';
  else                          recommendation = 'Review includes and reduce chained lookups; aim for clear enforcement when ready.';
  window.policySummaryRecommendation = recommendation;

}

// Reset the whole page back to its initial, empty state (the "Clear" button).
function clearAll() {
  if (domainInput)  domainInput.value = '';
  if (ipInput)      ipInput.value = '';
  if (recordInput)  recordInput.value = '';
  if (aInput)       aInput.value = '';
  if (mxInput)      mxInput.value = '';
  if (includeInput) includeInput.value = '';
  if (scenarioNote) scenarioNote.textContent = 'Select a scenario to preload data.';
  if (uploadStatus) uploadStatus.textContent = 'No file selected.';
  if (emailFileInput) emailFileInput.value = '';
  setResult('neutral', 'Run an evaluation to see the decision.');
  if (traceList) traceList.innerHTML = '';

  const speedoNode = document.getElementById('spf-speedometer');
  if (speedoNode) speedoNode.remove();

  renderCommercial(null);
  document.querySelectorAll('.scenario-card').forEach((el) => el.classList.remove('active'));
}

// Toggle the evaluate button's disabled/label state while a request is in flight.
function setLoading(isLoading) {
  if (!evaluateBtn) return;
  evaluateBtn.disabled  = isLoading;
  evaluateBtn.textContent = isLoading ? 'Evaluating...' : 'Evaluate SPF';
}

// ── Init ─────────────────────────────────────────────────────
// Bootstrap once the DOM is ready: build scenarios, wire buttons + tooltips, and
// auto-run an evaluation if a ?domain= parameter was passed (e.g. from the builder).
document.addEventListener('DOMContentLoaded', () => {
  loadScenarios();
  setResult('neutral', 'Run an evaluation to see the decision.');
  renderCommercial(null);

  if (emailFileInput) {
    emailFileInput.addEventListener('change', handleEmailFileUpload);
  }

  // Apply tooltips to all static elements that are already in the DOM
  applyTooltips();

  if (evaluateBtn) evaluateBtn.addEventListener('click', evaluateSpf);
  if (resetBtn)    resetBtn.addEventListener('click', clearAll);

  const urlParams    = new URLSearchParams(window.location.search);
  const domainParam  = urlParams.get('domain');
  const apiBaseParam = urlParams.get('apiBase');

  if (apiBaseParam) document.body.dataset.apiBaseUrl = apiBaseParam;

  if (domainParam) {
    domainInput.value = decodeURIComponent(domainParam);
    evaluateSpf();
  }
});