/**
 * spf.js — SPF POC / Live Auditor Logic
 * * WHAT THIS DOES:
 * ---------------
 * 1. Checks for ?domain= parameters on page load and automatically evaluates.
 * 2. Connects to the dynamic backend endpoint /api/spf/check.
 * 3. Injects a custom 10 DNS Lookup Speedometer with real-time flashing red error indicators.
 * 4. Renders an interactive waterfall evaluation mechanism trace timeline.
 */

// ── DOM Element Selectors ───────────────────────────────────
const domainInput = document.getElementById('domain-input');
const ipInput = document.getElementById('ip-input');
const recordInput = document.getElementById('record-input');
const aInput = document.getElementById('a-input');
const mxInput = document.getElementById('mx-input');
const includeInput = document.getElementById('include-input');
const evaluateBtn = document.getElementById('evaluate-btn');
const resetBtn = document.getElementById('reset-btn');

const resultBadge = document.getElementById('result-badge');
const resultSummary = document.getElementById('result-summary');
const traceList = document.getElementById('trace-list');
const policySummaryText = document.getElementById('policy-summary-text');
const commercialStatus = document.getElementById('commercial-status');
const commercialRisk = document.getElementById('commercial-risk');
const commercialRecommendation = document.getElementById('commercial-recommendation');
const commercialImpact = document.getElementById('commercial-impact');
const commercialHighlights = document.getElementById('commercial-highlights');

const scenarioGrid = document.getElementById('scenario-grid');
const scenarioNote = document.getElementById('scenario-note');

// Small HTML escape helper for safe insertion
function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Inject Speedometer Structural Styles ────────────────────
// Programmatically adds flashing red keyframe animations without modifying external CSS files
const style = document.createElement('style');
style.textContent = `
  @keyframes speedo-pulse {
    0% { background-color: #b91c1c; box-shadow: 0 0 4px #b91c1c; }
    50% { background-color: #ef4444; box-shadow: 0 0 12px #ef4444; }
    100% { background-color: #b91c1c; box-shadow: 0 0 4px #b91c1c; }
  }
  .speedo-flash-red {
    animation: speedo-pulse 0.8s infinite ease-in-out !important;
  }
`;
document.head.appendChild(style);

// ── Dynamic Speedometer Component Generation ────────────────
function injectSpeedometerDOM() {
  const resultCard = document.querySelector('.result-card');
  if (!resultCard) return;

  // Prevent duplicate injections if evaluate is clicked multiple times
  if (document.getElementById('spf-speedometer')) return;

  const speedoWrapper = document.createElement('div');
  speedoWrapper.id = 'spf-speedometer';
  speedoWrapper.style.cssText = 'margin: 16px 0; padding: 12px; background: var(--bg-strong); border: 1px solid var(--border); border-radius: 12px;';

  speedoWrapper.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; margin-bottom: 6px;">
      <span style="color: var(--muted); font-weight: 600;">10 DNS Lookup Speedometer</span>
      <span id="speedo-count" style="font-weight: 700; color: var(--ink);">0 / 10</span>
    </div>
    <div style="background: var(--border); height: 10px; border-radius: 999px; overflow: hidden; position: relative; width: 100%;">
      <div id="speedo-fill" style="height: 100%; width: 0%; background: var(--success); transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1), background-color 0.3s ease;"></div>
    </div>
    <div id="speedo-alert" style="display: none; margin-top: 10px; padding: 8px 12px; background: rgba(185,28,28,0.08); border: 1px solid rgba(185,28,28,0.3); color: var(--danger); border-radius: 8px; font-size: 0.78rem; font-weight: 600; text-align: center; font-family: 'JetBrains Mono', monospace;">
      ⚠️ SPF PermError: Too many DNS lookups
    </div>
  `;

  // Place speedometer right before the execution timeline list
  resultCard.insertBefore(speedoWrapper, traceList);
}

// Update Speedometer UI State
function updateSpeedometer(lookups) {
  injectSpeedometerDOM();
  
  const countEl = document.getElementById('speedo-count');
  const fillEl = document.getElementById('speedo-fill');
  const alertEl = document.getElementById('speedo-alert');

  if (!countEl || !fillEl || !alertEl) return;

  const count = parseInt(lookups) || 0;
  countEl.textContent = `${count} / 10`;

  // Calculate percentage fill capped at 100%
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

// ── Scenarios Dataset ───────────────────────────────────────
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

function applyScenario(scenario) {
  const { domain, ip } = scenario.data;
  if (domainInput) domainInput.value = domain;
  if (ipInput) ipInput.value = ip;
  if (scenarioNote) scenarioNote.textContent = scenario.note;
  evaluateSpf();
}

function getApiBaseUrl() {
  const configuredBase = document.body?.dataset?.apiBaseUrl;
  if (configuredBase) {
    return configuredBase.replace(/\/$/, '');
  }

  if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
    return window.location.origin;
  }

  return 'http://localhost:3000';
}

function getApiTargets() {
  const targets = [];
  const apiBaseUrl = getApiBaseUrl();
  if (apiBaseUrl) targets.push(apiBaseUrl);

  const localhost = 'http://localhost:3000';
  if (!targets.includes(localhost)) targets.push(localhost);

  return targets;
}

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

// ── Core Evaluation Logic — API Integration ─────────────────
async function evaluateSpf() {
  const domain = domainInput?.value.trim();
  const ip = ipInput?.value.trim();

  // Reset display containers
  if (traceList) traceList.innerHTML = '';
  if (recordInput) recordInput.value = '';
  if (aInput) aInput.value = '';
  if (mxInput) mxInput.value = '';
  if (includeInput) includeInput.value = '';
  updateSpeedometer(0);

  if (!domain || !ip) {
    setResult('neutral', 'Enter a domain and sender IP to evaluate.');
    return;
  }

  setLoading(true);

  try {
    const data = await fetchSpfEvaluation(domain, ip);

    // Populate standard visual elements
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

    // Handle Speedometer logic from server response counts
    const totalLookups = data.lookupCount ?? data.dnsLookups ?? data.lookups ?? 0;
    updateSpeedometer(totalLookups);

    // Update main status tags
    setResult(mapResultClass(data.result || 'neutral'), data.reason || 'SPF evaluation complete.');
    
    // Construct waterfall trace & metadata metrics
    renderTrace(data.trace || [], data.result);
    renderPolicySummary(data);
    renderCommercial(data.commercial || null);

  } catch (err) {
    console.error("Critical Connection Error:", err);
    setResult('fail', `Server Connection Offline: Unreachable API endpoint.`);
    if (traceList) {
      traceList.innerHTML = `
        <div class="trace-row" style="border-color: var(--danger); background: rgba(185,28,28,0.05);">
          <strong style="color: var(--danger);">⚠️ HTTP Fetch Exception</strong>
          <span>Failed to connect to backend server. Ensure node/python backend service layer is running on correct port.</span>
        </div>`;
    }
  } finally {
    setLoading(false);
  }
}

// ── Custom Waterfall Trace List Builder ──────────────────────
function renderTrace(steps, finalResult) {
  if (!traceList) return;
  traceList.innerHTML = '';

  if (!steps || !steps.length) {
    traceList.innerHTML = '<div class="trace-row"><strong>No trace returned</strong><span>The backend did not return a mechanism path for this domain and IP.</span></div>';
    return;
  }
  // Compact display: show first N steps and the final step, with a toggle to expand full trace
  const MAX_PREVIEW = 4;
  const preview = steps.slice(0, MAX_PREVIEW);
  const lastStep = steps[steps.length - 1];

  function makeRow(step, index, isFinal) {
    const row = document.createElement('div');
    row.className = 'trace-row';
    row.style.cssText = 'display: flex; flex-direction: column; position: relative; padding-left: 16px; margin-bottom: 8px; border-left: 3px solid var(--border);';

    let stepTitle = `Step ${index + 1}: Checking ${step.mechanism || 'Mechanism'}`;
    let outcomeText = step.detail || 'Evaluating criteria path rule.';

    if (isFinal) {
      stepTitle = `Step ${index + 1}: Path Match Finalized!`;
      row.style.borderLeftColor = 'var(--success)';
    } else {
      row.style.borderLeftColor = 'rgba(16,122,127,0.12)';
    }

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

    // Toggle details per-row
    const toggle = row.querySelector('.trace-toggle-details');
    const body = row.querySelector('.trace-row-body');
    toggle.addEventListener('click', () => {
      const expanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!expanded));
      body.style.display = expanded ? 'none' : 'block';
      toggle.textContent = expanded ? 'Details' : 'Hide';
    });

    return row;
  }

  // Append preview rows
  preview.forEach((s, i) => traceList.appendChild(makeRow(s, i, false)));

  // If there are more steps, add a collapsed count and reveal button
  if (steps.length > MAX_PREVIEW + 1) {
    const remainingCount = steps.length - (MAX_PREVIEW + 1);
    const collapsed = document.createElement('div');
    collapsed.className = 'trace-collapsed';
    collapsed.style.cssText = 'padding: 8px 12px; margin-bottom:8px; color: var(--muted); background: rgba(243, 239, 232, 0.95); border-radius: 8px;';
    collapsed.innerHTML = `<button class="btn-secondary" id="show-full-trace">Show ${remainingCount} more steps</button>`;
    traceList.appendChild(collapsed);

    collapsed.querySelector('#show-full-trace').addEventListener('click', (e) => {
      // remove the collapsed node and append the middle steps
      collapsed.remove();
      const middle = steps.slice(MAX_PREVIEW, steps.length - 1);
      middle.forEach((s, idx) => traceList.appendChild(makeRow(s, MAX_PREVIEW + idx, false)));
      // append final step
      traceList.appendChild(makeRow(lastStep, steps.length - 1, true));
    });
  } else {
    // append middle steps (if any) and final step
    const middle = steps.slice(MAX_PREVIEW, steps.length - 1);
    middle.forEach((s, idx) => traceList.appendChild(makeRow(s, MAX_PREVIEW + idx, false)));
    traceList.appendChild(makeRow(lastStep, steps.length - 1, true));
  }
}

// ── Secondary Helper Controllers ─────────────────────────────
function mapResultClass(result) {
  const normalized = String(result || '').toLowerCase();
  if (['pass', 'fail', 'softfail', 'neutral'].includes(normalized)) return normalized;
  if (['none', 'permerror', 'temperror'].includes(normalized)) return 'neutral';
  return 'neutral';
}

function setResult(result, summary) {
  if (!resultBadge || !resultSummary) return;
  const display = String(result || '').toUpperCase();
  resultBadge.className = `result-badge ${result}`;
  resultBadge.textContent = display || 'NEUTRAL';
  resultSummary.textContent = summary;
}

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

  commercialStatus.textContent = summary.status || 'Unknown';
  commercialRisk.textContent = summary.riskScore != null ? `${summary.riskScore}%` : 'N/A';
  commercialRecommendation.textContent = summary.recommendation || 'Review SPF configuration and retry.';
  commercialImpact.textContent = summary.businessImpact || 'Authentication result requires review.';

  if (Array.isArray(summary.highlights) && summary.highlights.length) {
    commercialHighlights.innerHTML = `<ul>${summary.highlights.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
  } else {
    commercialHighlights.innerHTML = '<p style="color: var(--muted); margin: 0;">No highlight details available.</p>';
  }
}

function renderPolicySummary(data) {
  if (!policySummaryText) return;
  const record = String(data.record || '');
  const includeRecords = data.includeRecords || {};
  const includes = Array.isArray(includeRecords) ? includeRecords : Object.keys(includeRecords || {});
  const ip4s = (record.match(/ip4:[^\s]+/g) || []).map((t) => t.replace('ip4:', ''));
  const redirects = (record.match(/redirect=[^\s]+/g) || []).map((t) => t.replace('redirect=', ''));
  const matched = data.matchedMechanism || null;
  const lookups = Number(data.lookupCount || data.dnsLookups || 0);

  if (!record) {
    policySummaryText.innerHTML = `<strong>No SPF record found</strong><div style="color:var(--muted); margin-top:6px;">This domain has no SPF TXT record — publish a policy to prevent unauthorized senders.</div>`;
    return;
  }

  // Determine enforcement level
  let enforcement = 'No explicit enforcement';
  if (/\-all\b/.test(record)) enforcement = 'Strict enforcement (-all)';
  else if (/~all\b/.test(record)) enforcement = 'Soft enforcement (~all) — monitoring';
  else if (/\?all\b/.test(record)) enforcement = 'Neutral (?all) — no claim';
  else if (/\+all\b/.test(record)) enforcement = 'Permissive (+all) — allows any sender';

  // Build quick highlights
  const highlights = [];
  highlights.push(enforcement);
  if (matched) highlights.push(`Matched mechanism: ${matched}`);
  if (ip4s.length) highlights.push(`${ip4s.length} direct IP${ip4s.length>1?'s':''}`);
  if (includes.length) highlights.push(`${includes.length} include/redirect domain${includes.length>1?'s':''}`);
  if (redirects.length) highlights.push(`Redirects to ${redirects.join(', ')}`);
  if (lookups > 10) highlights.push(`High DNS lookup count: ${lookups} (may cause PermError)`);

  // Recommendation
  let recommendation = 'No immediate action required.';
  if (/\-all\b/.test(record)) recommendation = 'Policy is enforcing; monitor and maintain known senders.';
  else if (/~all\b/.test(record)) recommendation = 'Consider moving to -all after validating all legitimate senders.';
  else if (!record) recommendation = 'Publish an SPF record to state authorized senders.';
  else recommendation = 'Review includes and reduce chained lookups; aim for clear enforcement when ready.';

  // Compose compact HTML output
  policySummaryText.innerHTML = `
    <div style="font-weight:700; margin-bottom:6px;">${escapeHtml(enforcement)}</div>
    <div style="color:var(--muted); margin-bottom:8px;">${escapeHtml(recommendation)}</div>
    <div style="font-size:0.92rem; margin-top:6px;">
      ${highlights.map((h) => `<span style="display:inline-block; margin-right:8px; color:var(--muted);">• ${escapeHtml(h)}</span>`).join('')}
    </div>
    <div style="margin-top:8px; color:var(--muted); font-size:0.86rem;">Record: <code style="font-family: 'JetBrains Mono', monospace;">${escapeHtml(record)}</code></div>
  `;
}

function clearAll() {
  if (domainInput) domainInput.value = '';
  if (ipInput) ipInput.value = '';
  if (recordInput) recordInput.value = '';
  if (aInput) aInput.value = '';
  if (mxInput) mxInput.value = '';
  if (includeInput) includeInput.value = '';
  if (scenarioNote) scenarioNote.textContent = 'Select a scenario to preload data.';
  setResult('neutral', 'Run an evaluation to see the decision.');
  if (traceList) traceList.innerHTML = '';
  
  // Clean remove custom speedometer node on structural reset
  const speedoNode = document.getElementById('spf-speedometer');
  if (speedoNode) speedoNode.remove();

  renderCommercial(null);
  document.querySelectorAll('.scenario-card').forEach((el) => el.classList.remove('active'));
}

function setLoading(isLoading) {
  if (!evaluateBtn) return;
  evaluateBtn.disabled = isLoading;
  evaluateBtn.textContent = isLoading ? 'Evaluating...' : 'Evaluate SPF';
}

// ── Application Initialization Lifecycle Router ──────────────
document.addEventListener('DOMContentLoaded', () => {
  loadScenarios();
  setResult('neutral', 'Run an evaluation to see the decision.');
  renderCommercial(null);

  if (evaluateBtn) evaluateBtn.addEventListener('click', evaluateSpf);
  if (resetBtn) resetBtn.addEventListener('click', clearAll);

  // Requirement 1: Capture inbound route parameter and execute immediately
  const urlParams = new URLSearchParams(window.location.search);
  const domainParam = urlParams.get('domain');
  const apiBaseParam = urlParams.get('apiBase');

  if (apiBaseParam) {
    document.body.dataset.apiBaseUrl = apiBaseParam;
  }
  
  if (domainParam) {
    domainInput.value = decodeURIComponent(domainParam);
    // Optional fallback vector: Prepopulate standard workspace testing IP if empty
    // Do not auto-fill an IP — user should supply the sending MTA IP from message headers.
    evaluateSpf();
   }
});
