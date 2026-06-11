/**
 * spf-simulator.js — SPF Softfail vs Hardfail Simulator
 * Dynamic backend-driven sandbox.
 */

const scenarios = [
  {
    key: 'ceo-fraud',
    label: 'CEO Fraud',
    tag: 'BEC Attack',
    domain: 'company.com',
    attackerIP: '185.220.101.5',
    description: 'A spoofed executive message that should be blocked when policy is strict.'
  },
  {
    key: 'phishing',
    label: 'Banking Phish',
    tag: 'Phishing Attack',
    domain: 'dbs.com',
    attackerIP: '45.33.32.156',
    description: 'A fake bank alert sent from an unauthorised sender.'
  },
  {
    key: 'legit-newsletter',
    label: 'Legitimate Newsletter',
    tag: 'Authorised Sender',
    domain: 'company.com',
    attackerIP: '167.89.0.1',
    description: 'A legitimate mail source that should pass SPF cleanly.'
  },
  {
    key: 'no-spf',
    label: 'No SPF Record',
    tag: 'Misconfigured Domain',
    domain: 'vulnerable.org',
    attackerIP: '104.21.0.99',
    description: 'A domain with no SPF record published in DNS.'
  }
];

const nodes = {
  scenarioTabs: document.getElementById('scenario-tabs'),
  targetDomain: document.getElementById('target-domain'),
  attackerIP: document.getElementById('attacker-ip'),
  runButton: document.getElementById('run-simulation'),
  resetButton: document.getElementById('reset-simulation'),
  summary: document.getElementById('simulation-summary'),
  emailPreview: document.getElementById('email-preview'),
  spfResultBar: document.getElementById('spf-result-bar'),
  softSteps: document.getElementById('steps-soft'),
  hardSteps: document.getElementById('steps-hard'),
  softView: document.getElementById('view-soft'),
  hardView: document.getElementById('view-hard'),
  softVerdict: document.getElementById('verdict-soft'),
  hardVerdict: document.getElementById('verdict-hard'),
  insight: document.getElementById('insight-text'),
};

let activeScenarioKey = scenarios[0].key;

function renderScenarioTabs() {
  nodes.scenarioTabs.innerHTML = scenarios.map((scenario) => `
    <button class="scenario-tab${scenario.key === activeScenarioKey ? ' active' : ''}" data-scenario="${scenario.key}">
      ${scenario.label}
      <span class="scenario-tag">${scenario.tag}</span>
    </button>
  `).join('');

  nodes.scenarioTabs.querySelectorAll('button[data-scenario]').forEach((button) => {
    button.addEventListener('click', () => {
      const scenario = scenarios.find((item) => item.key === button.dataset.scenario);
      if (!scenario) return;
      activeScenarioKey = scenario.key;
      populateInputs(scenario);
      renderScenarioTabs();
    });
  });
}

function populateInputs(scenario) {
  nodes.targetDomain.value = scenario.domain;
  nodes.attackerIP.value = scenario.attackerIP;
  nodes.summary.textContent = scenario.description;
  renderSnapshot({
    domain: scenario.domain,
    attackerIP: scenario.attackerIP,
    scenario: scenario.label,
    description: scenario.description,
  });
}

function renderSnapshot({ domain, attackerIP, scenario, description }) {
  nodes.emailPreview.innerHTML = [
    row('Target domain', domain),
    row('Attacker IP', attackerIP),
    row('Scenario', scenario),
    row('Description', description),
  ].join('');

  nodes.spfResultBar.innerHTML = `
    <span class="spf-result-label">Sandbox status</span>
    <span class="spf-result-val">Ready to run</span>
    <span class="spf-pill none">IDLE</span>
  `;
}

function row(label, value) {
  return `
    <div class="email-row">
      <span class="email-label">${escapeHtml(label)}</span>
      <span class="email-val">${escapeHtml(value)}</span>
    </div>
  `;
}

function resultClass(result) {
  const normalized = String(result || '').toLowerCase();
  if (normalized === 'pass') return 'pass';
  if (normalized === 'softfail') return 'softfail';
  if (normalized === 'fail') return 'fail';
  return 'none';
}

function verdictMeta(result, policy) {
  const normalized = String(result || '').toLowerCase();
  if (normalized === 'pass') {
    return {
      label: 'Delivered normally',
      detail: 'The sender is authorized, so the message is accepted.',
      icon: '✅',
      className: 'verdict-pass',
    };
  }

  if (policy === '~all') {
    return {
      label: 'Delivered with warning',
      detail: 'The message fails SPF but is still delivered under softfail.',
      icon: '⚠️',
      className: 'verdict-warn',
    };
  }

  return {
    label: 'Rejected at SMTP layer',
    detail: 'The server refuses the message under hardfail policy.',
    icon: '🚫',
    className: 'verdict-danger',
  };
}

function renderSteps(container, steps) {
  container.innerHTML = steps.map((step) => `
    <div class="step-row">
      <div class="step-dot dot-${step.dot}">${step.dot === 'pass' ? '✓' : step.dot === 'fail' ? '✕' : step.dot === 'warn' ? '!' : 'i'}</div>
      <div>
        <div class="step-title">${escapeHtml(step.title)}</div>
        <div class="step-sub">${escapeHtml(step.sub)}</div>
      </div>
    </div>
  `).join('');
}

function renderClientView(container, data) {
  if (!data) {
    container.innerHTML = '';
    return;
  }

  container.innerHTML = `
    <div class="client-shell">
      <div class="client-banner">${escapeHtml(data.banner)}</div>
      <div class="client-message">
        <strong>Inbox view</strong>
        <p>${escapeHtml(data.message)}</p>
      </div>
      <div class="client-meta">
        <span>From: ${escapeHtml(data.from)}</span>
        <span>Status: ${escapeHtml(data.status)}</span>
      </div>
    </div>
  `;
}

function renderTerminalView(container, terminalLog, rejected) {
  container.innerHTML = `
    <div class="terminal-shell">
      <div class="terminal-header">SMTP Log Terminal</div>
      <pre class="terminal-lines">${escapeHtml(terminalLog)}</pre>
      ${rejected ? '<div class="terminal-reject">Rejected before delivery.</div>' : '<div class="terminal-accept">Accepted for delivery.</div>'}
    </div>
  `;
}

function renderVerdict(container, meta) {
  container.className = `verdict-box ${meta.className}`;
  container.innerHTML = `
    <span class="verdict-icon">${meta.icon}</span>
    <div>
      <div class="verdict-label">${escapeHtml(meta.label)}</div>
      <div class="verdict-detail">${escapeHtml(meta.detail)}</div>
    </div>
  `;
}

function renderSummary(data) {
  nodes.summary.innerHTML = `
    SPF record: <strong>${escapeHtml(data.record || 'No SPF record found')}</strong> ·
    DNS lookups: <strong>${data.lookupCount || 0}</strong> ·
    Result: <strong>${escapeHtml(data.summary)}</strong>
  `;

  nodes.spfResultBar.innerHTML = `
    <span class="spf-result-label">Evaluation</span>
    <span class="spf-result-val">${escapeHtml(data.summary)}</span>
    <span class="spf-pill ${resultClass(data.soft.result)}">${escapeHtml(data.soft.result.toUpperCase())}</span>
  `;
}

function renderPanels(response) {
  renderSteps(nodes.softSteps, response.soft.steps || []);
  renderSteps(nodes.hardSteps, response.hard.steps || []);

  const softMeta = verdictMeta(response.soft.result, '~all');
  const hardMeta = verdictMeta(response.hard.result, '-all');

  renderVerdict(nodes.softVerdict, softMeta);
  renderVerdict(nodes.hardVerdict, hardMeta);

  renderClientView(nodes.softView, response.soft.clientView ? {
    banner: response.soft.banner,
    message: 'This email failed authentication but was delivered to the inbox with a warning banner.',
    from: response.soft.clientView.from,
    status: response.soft.clientView.status,
  } : null);

  renderTerminalView(nodes.hardView, response.hard.terminalLog, response.hard.result === 'fail');
}

async function runSimulation() {
  const domain = nodes.targetDomain.value.trim();
  const attackerIP = nodes.attackerIP.value.trim();

  if (!domain || !attackerIP) {
    nodes.summary.textContent = 'Enter a target domain and attacker IP first.';
    return;
  }

  setLoading(true);

  try {
    const response = await fetch('/api/spf/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, attackerIP }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'SPF simulation failed.');
    }

    renderSummary(data);
    renderPanels(data);
    nodes.insight.innerHTML = data.summary;
  } catch (error) {
    const message = error?.message || 'SPF simulation failed.';
    nodes.summary.textContent = message;
    nodes.softSteps.innerHTML = errorMarkup(message);
    nodes.hardSteps.innerHTML = errorMarkup(message);
    nodes.softView.innerHTML = '';
    nodes.hardView.innerHTML = '';
    nodes.softVerdict.innerHTML = '';
    nodes.hardVerdict.innerHTML = '';
    nodes.insight.textContent = message;
  } finally {
    setLoading(false);
  }
}

function errorMarkup(message) {
  return `
    <div class="step-row">
      <div class="step-dot dot-fail">✕</div>
      <div>
        <div class="step-title">Backend error</div>
        <div class="step-sub">${escapeHtml(message)}</div>
      </div>
    </div>
  `;
}

function resetSimulation() {
  populateInputs(scenarios.find((scenario) => scenario.key === activeScenarioKey) || scenarios[0]);
  nodes.softSteps.innerHTML = '';
  nodes.hardSteps.innerHTML = '';
  nodes.softView.innerHTML = '';
  nodes.hardView.innerHTML = '';
  nodes.softVerdict.innerHTML = '';
  nodes.hardVerdict.innerHTML = '';
  nodes.insight.textContent = 'Choose a scenario and run the backend simulation to compare softfail and hardfail behavior.';
}

function setLoading(isLoading) {
  nodes.runButton.disabled = isLoading;
  nodes.runButton.textContent = isLoading ? 'Running...' : 'Run simulation';
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

nodes.runButton.addEventListener('click', runSimulation);
nodes.resetButton.addEventListener('click', resetSimulation);

renderScenarioTabs();
populateInputs(scenarios[0]);
nodes.insight.textContent = 'Choose a scenario and run the backend simulation to compare softfail and hardfail behavior.';
