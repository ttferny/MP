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
const commercialStatus = document.getElementById('commercial-status');
const commercialRisk = document.getElementById('commercial-risk');
const commercialRecommendation = document.getElementById('commercial-recommendation');
const commercialImpact = document.getElementById('commercial-impact');
const commercialHighlights = document.getElementById('commercial-highlights');

const scenarioGrid = document.getElementById('scenario-grid');
const scenarioNote = document.getElementById('scenario-note');

const scenarios = [
  {
    key: 'google',
    title: 'Major Provider',
    note: 'Live DNS example. Result depends on the chosen IP.',
    data: {
      domain: 'google.com',
      ip: '64.233.160.0'
    }
  },
  {
    key: 'strict',
    title: 'Strict -all Policy',
    note: 'Domains like example.com publish -all for testing.',
    data: {
      domain: 'example.com',
      ip: '203.0.113.55'
    }
  },
  {
    key: 'marketing',
    title: 'Marketing Sender',
    note: 'Try an ESP domain to see include chains.',
    data: {
      domain: 'sendgrid.net',
      ip: '167.89.0.0'
    }
  },
  {
    key: 'custom',
    title: 'Your Own Domain',
    note: 'Replace with any domain you want to test.',
    data: {
      domain: 'example.org',
      ip: '203.0.113.99'
    }
  }
];

function loadScenarios() {
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
  domainInput.value = domain;
  ipInput.value = ip;
  scenarioNote.textContent = scenario.note;
  evaluateSpf();
}

async function evaluateSpf() {
  const domain = domainInput.value.trim();
  const ip = ipInput.value.trim();

  traceList.innerHTML = '';
  recordInput.value = '';
  aInput.value = '';
  mxInput.value = '';
  includeInput.value = '';

  if (!domain || !ip) {
    setResult('neutral', 'Enter a domain and sender IP to evaluate.');
    return;
  }

  setLoading(true);

  try {
    const response = await fetch('/api/spf/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, ip })
    });

    const data = await response.json();
    if (!response.ok) {
      setResult('neutral', data.error || 'SPF lookup failed.');
      return;
    }

    recordInput.value = data.record || '(no SPF record found)';
    aInput.value = (data.dns?.aRecords || []).join(', ') || '(none)';
    const mxRecords = data.dns?.mxRecords || [];
    mxInput.value = mxRecords.length
      ? mxRecords.map((mx) => (typeof mx === 'string' ? mx : `${mx.exchange} (${mx.priority})`)).join(', ')
      : '(none)';

    const includeEntries = Object.entries(data.includeRecords || {});
    includeInput.value = includeEntries.length
      ? includeEntries.map(([key, value]) => `${key} = ${value}`).join('\n')
      : '(none)';

    setResult(mapResultClass(data.result || 'neutral'), data.reason || 'SPF evaluation complete.');
    renderTrace(data.trace || []);
    renderCommercial(data.commercial || null);
  } catch (err) {
    setResult('neutral', `Could not reach server: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

function mapResultClass(result) {
  const normalized = String(result || '').toLowerCase();
  if (['pass', 'fail', 'softfail', 'neutral'].includes(normalized)) return normalized;
  if (['none', 'permerror', 'temperror'].includes(normalized)) return 'neutral';
  return 'neutral';
}

function setResult(result, summary) {
  const display = String(result || '').toUpperCase();
  resultBadge.className = `result-badge ${result}`;
  resultBadge.textContent = display || 'NEUTRAL';
  resultSummary.textContent = summary;
}

function renderTrace(steps) {
  if (!steps.length) {
    traceList.innerHTML = '<div class="trace-row"><strong>No steps</strong><span>Provide a domain and sender IP to evaluate.</span></div>';
    return;
  }

  steps.forEach((step) => {
    const row = document.createElement('div');
    row.className = 'trace-row';
    row.innerHTML = `<strong>${step.mechanism}</strong><span>${step.detail} | ${step.outcome}</span>`;
    traceList.appendChild(row);
  });
}

function renderCommercial(summary) {
  if (!summary) {
    commercialStatus.textContent = 'Inconclusive';
    commercialRisk.textContent = '--';
    commercialRecommendation.textContent = 'Run an evaluation to see guidance.';
    commercialImpact.textContent = 'Authentication details will appear here.';
    commercialHighlights.innerHTML = '';
    return;
  }

  commercialStatus.textContent = summary.status || 'Inconclusive';
  commercialRisk.textContent = typeof summary.riskScore === 'number' ? `${summary.riskScore}/100` : '--';
  commercialRecommendation.textContent = summary.recommendation || 'Review SPF configuration.';
  commercialImpact.textContent = summary.businessImpact || 'Authentication result requires review.';

  const highlights = Array.isArray(summary.highlights) ? summary.highlights : [];
  commercialHighlights.innerHTML = highlights.length
    ? highlights.map((item) => `<span>${item}</span>`).join('')
    : '';
}

function clearAll() {
  domainInput.value = '';
  ipInput.value = '';
  recordInput.value = '';
  aInput.value = '';
  mxInput.value = '';
  includeInput.value = '';
  scenarioNote.textContent = 'Select a scenario to preload data.';
  setResult('neutral', 'Run an evaluation to see the decision.');
  traceList.innerHTML = '';
  renderCommercial(null);
  document.querySelectorAll('.scenario-card').forEach((el) => el.classList.remove('active'));
}

function setLoading(isLoading) {
  evaluateBtn.disabled = isLoading;
  evaluateBtn.textContent = isLoading ? 'Evaluating...' : 'Evaluate SPF';
}

evaluateBtn.addEventListener('click', evaluateSpf);
resetBtn.addEventListener('click', clearAll);

loadScenarios();
setResult('neutral', 'Run an evaluation to see the decision.');
renderCommercial(null);
