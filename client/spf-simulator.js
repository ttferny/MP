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
    domain: 'news.example.com',
    attackerIP: '167.89.0.1',
    description: 'A legitimate mail source that should pass SPF cleanly.'
  },
  {
    key: 'misconfigured',
    label: 'No SPF Record',
    tag: 'Misconfigured Domain',
    domain: 'vulnerable.org',
    attackerIP: '104.21.0.99',
    description: 'A domain with no or weak SPF policy published in DNS.'
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
  // Indicate the selected scenario in the status bar
  nodes.spfResultBar.innerHTML = `
    <span class="spf-result-label">Sandbox status</span>
    <span class="spf-result-val">Loaded scenario: ${escapeHtml(scenario.label)}</span>
    <span class="spf-pill none">${escapeHtml(scenario.key)}</span>
  `;
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
  // Add hover tooltips for timeline items (mechanism details when available)
  container.innerHTML = steps.map((step) => {
    const mechanism = step.mechanism || step.mechanic || '';
    const qualifier = step.qualifier || step.q || '';
    const detail = step.detail || step.sub || '';
    const tooltip = [mechanism && `Mechanism: ${mechanism}`, qualifier && `Qualifier: ${qualifier}`, detail && `Detail: ${detail}`].filter(Boolean).join(' · ');

    return `
      <div class="step-row" title="${escapeHtml(tooltip)}" aria-label="${escapeHtml(tooltip)}">
        <div class="step-dot dot-${step.dot}">${step.dot === 'pass' ? '✓' : step.dot === 'fail' ? '✕' : step.dot === 'warn' ? '!' : 'i'}</div>
        <div>
          <div class="step-title">${escapeHtml(step.title)}</div>
          <div class="step-sub">${escapeHtml(step.sub)}</div>
        </div>
      </div>
    `;
  }).join('');
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
    message: (String(response.soft.result || '').toLowerCase() === 'pass') ? 'This email passed SPF and was delivered normally.' : 'This email failed SPF but was delivered to the inbox with a warning banner.',
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

  // Clear previous run UI to avoid stale traces
  nodes.softSteps.innerHTML = '';
  nodes.hardSteps.innerHTML = '';
  nodes.softView.innerHTML = '';
  nodes.hardView.innerHTML = '';
  nodes.softVerdict.innerHTML = '';
  nodes.hardVerdict.innerHTML = '';
  nodes.spfResultBar.innerHTML = `
    <span class="spf-result-label">Evaluation</span>
    <span class="spf-result-val">Running simulation...</span>
    <span class="spf-pill running">${escapeHtml(activeScenarioKey || 'manual')}</span>
  `;

  setLoading(true);

  try {
    const response = await fetch('/api/spf/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, attackerIP, scenarioKey: activeScenarioKey }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'SPF simulation failed.');
    }

    renderSummary(data);
    renderPanels(data);
      renderExplanations(data);
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

function renderExplanations(response) {
  // Provide a richer, scenario-aware explanation that links SPF to broader email auth
  const lookups = response.lookupCount || 0;
  const soft = response.soft || {};
  const hard = response.hard || {};
  const record = response.record || '(no SPF record)';
  const domain = response.domain || response.recordDomain || nodes.targetDomain.value || '';
  const scenarioKey = response.scenarioKey || response.scenario || nodes.spfResultBar?.querySelector('.spf-pill')?.textContent || '';

  // Concise, commercial-friendly key insight summary
  const atAGlance = `${escapeHtml((soft.result||'unknown').toUpperCase())} (soft) · ${escapeHtml((hard.result||'unknown').toUpperCase())} (hard) — matched: ${escapeHtml(response.matchedMechanism || soft.matchedMechanism || hard.matchedMechanism || 'none')}`;

  // Compact protocol context hidden behind a 'More' disclosure for learners who want depth
  const protocolContext = `
    <details class="explain-more"><summary>More: protocol context & technical notes</summary>
      <div class="explain-more-body">
        <h4>Protocol context</h4>
        <ul>
          <li><strong>SPF purpose:</strong> publish which IPs can send mail for this domain (envelope MAIL FROM).</li>
          <li><strong>SPF vs DKIM:</strong> SPF checks sending IP; DKIM signs content/headers — both feed DMARC.</li>
          <li><strong>SPF → DMARC:</strong> For SPF to help DMARC, SPF-authenticated domain must align with From:.</li>
          <li><strong>Tip:</strong> use <code>-all</code> only after authorising all legitimate senders and enabling DKIM.</li>
        </ul>
      </div>
    </details>
  `;

  // Scenario-specific explanation snippets (help students relate the outcome to the scenario)
  const attackerIP = response.attackerIP || nodes.attackerIP.value || '';
  const domainLabel = domain || nodes.targetDomain.value || '';
  const matched = response.matchedMechanism || soft.matchedMechanism || hard.matchedMechanism || '';
  const softNorm = String(soft.result || '').toLowerCase();
  const hardNorm = String(hard.result || '').toLowerCase();
  const scenario = scenarios.find((item) => item.key === scenarioKey);
  const scenarioLabel = scenario ? scenario.label : '';
  const usedDefaultScenario = scenario && scenario.domain === domainLabel && scenario.attackerIP === attackerIP;

  let scenarioNote = '';
  if (scenarioLabel) {
    const actualResult = softNorm === 'pass' && hardNorm === 'pass'
      ? 'passes cleanly under both policies'
      : softNorm === 'softfail' && hardNorm === 'fail'
        ? 'is suspicious under ~all and rejected under -all'
        : softNorm === 'pass' && hardNorm === 'fail'
          ? 'passes under soft policy but is rejected by strict -all'
          : `returns ${soft.result || hard.result || 'unknown'} status`; 

    if (scenarioKey === 'ceo-fraud') {
      scenarioNote = `<p><strong>CEO Fraud:</strong> this executive spoof scenario ${actualResult}. The record delegates trust with an <code>include</code>, but the attacker IP is not authorised by the approved range.</p>`;
    } else if (scenarioKey === 'phishing') {
      scenarioNote = `<p><strong>Banking Phish:</strong> this fake bank alert scenario ${actualResult}. A strict <code>-all</code> policy rejects unauthorised senders as intended.</p>`;
    } else if (scenarioKey === 'legit-newsletter') {
      scenarioNote = `<p><strong>Legitimate newsletter:</strong> this newsletter scenario ${actualResult}. ${softNorm === 'pass' ? 'The attacker IP is authorised or included in the ESP record.' : 'The attacker IP is not authorised by the newsletter SPF policy.'}</p>`;
    } else if (scenarioKey === 'misconfigured' || record.includes('?all')) {
      scenarioNote = `<p><strong>Misconfigured:</strong> this weak policy scenario ${actualResult}. The record makes no strong claim, so spoofing protection is limited.</p>`;
    }

    if (!usedDefaultScenario && scenarioLabel) {
      scenarioNote += `<p class="explain-note-small">Custom input overrides the default ${escapeHtml(scenarioLabel)} scenario values.</p>`;
    }
  }

  if (!scenarioNote && domainLabel) {
    scenarioNote = `<p><strong>Note:</strong> this simulation evaluated <strong>${escapeHtml(domainLabel)}</strong> from <strong>${escapeHtml(attackerIP)}</strong>. The SPF outcome ${softNorm === 'pass' && hardNorm === 'pass' ? 'passes cleanly' : softNorm === 'softfail' && hardNorm === 'fail' ? 'flags the sender as suspicious' : 'is inconclusive'}.</p>`;
  }

  // Business impact: concise sentence reflecting actual results
  let businessRaw = '';
  if (softNorm === 'pass' && hardNorm === 'pass') {
    businessRaw = `${domainLabel} — sender ${attackerIP} is authorised; mail is delivered.`;
  } else if (softNorm === 'softfail' && hardNorm === 'fail') {
    businessRaw = `${domainLabel} — under ~all the mail is delivered with a warning; under -all it is rejected.`;
  } else if (softNorm === 'pass' && hardNorm === 'fail') {
    businessRaw = `${domainLabel} — delivery depends on receiver policy; passes loose policies but rejected with strict (-all).`;
  } else if (softNorm === 'softfail') {
    businessRaw = `${domainLabel} — sender ${attackerIP} is suspicious (softfail): delivered with warning.`;
  } else if (hardNorm === 'fail') {
    businessRaw = `${domainLabel} — sender ${attackerIP} is unauthorised and will be rejected by strict receivers.`;
  } else {
    businessRaw = `${domainLabel} — SPF result: ${soft.result || hard.result || 'unknown'}.`;
  }

  // Technical cause: prefer explicit mechanism info
  let techRaw = matched || 'No mechanism matched';
  if (matched && matched.toLowerCase().includes('ip4')) techRaw = `Matched IP mechanism (${matched})`;
  else if (matched && matched.toLowerCase().includes('include')) techRaw = `Matched include (${matched})`;

  const business = escapeHtml(businessRaw);
  const tech = escapeHtml(techRaw);
  const recommend = escapeHtml((hardNorm === 'fail' ? 'Tighten SPF (-all) and ensure DKIM for legitimate senders.' : 'Review includes and authorised senders; consider -all when fully tested.'));
  const quick = escapeHtml((matched && matched.toLowerCase().includes('ip4')) ? `Confirm ${attackerIP} is listed in the SPF record or remove unintended IPs.` : 'Inspect include records and add missing ESP entries; re-run simulation.');

  const boxes = `
    <div class="insight-grid">
      <div class="insight-box business">
        <div class="box-title">Business impact</div>
        <div class="box-body">${business}</div>
      </div>
      <div class="insight-box tech">
        <div class="box-title">Technical cause</div>
        <div class="box-body">${tech}</div>
      </div>
      <div class="insight-box action">
        <div class="box-title">Recommended action</div>
        <div class="box-body">${recommend}</div>
      </div>
      <div class="insight-box quick">
        <div class="box-title">Quick win</div>
        <div class="box-body">${quick}</div>
      </div>
    </div>
    ${protocolContext}
    <div class="explain-note">${scenarioNote}</div>
  `;

  const html = `
    <div class="explain-run compact">
      <h3>Key insight</h3>
      <p class="at-a-glance">${escapeHtml(atAGlance)}</p>
      ${boxes}
    </div>
  `;

  nodes.insight.innerHTML = html;

  // Mark todo item complete
  try { /* noop: UI only */ } catch (e) {}
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
