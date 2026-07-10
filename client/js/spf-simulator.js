/**
 * ============================================================
 * spf-simulator.js — Interactive SPF Learning Experience
 * ============================================================
 *
 * BUSINESS PITCH:
 * A guided, beginner-friendly "story mode" for SPF. The user picks a real-world
 * scenario (approved sender, spoofed CEO, phishing, third-party ESP, etc.) and
 * the page shows — side by side — how a SOFT warns(~all) vs a HARD rejects(-all) policy would
 * treat that same email.
 *
 * TECHNICAL:
 * Client-side only for tab scenarios; data mirrors spfRoutes simulator keys.
 * renderSimulation() drives soft/hard step lists and verdict boxes.
 *
 *  * WHY IT MATTERS (pitch note):
 * ----------------------------
 * This page sells the *value* of strict enforcement. By replaying attacks in a
 * safe sandbox, it makes an abstract DNS rule tangible: "with -all, this fake
 * CEO email gets rejected; with ~all it still lands with a warning."
 *
 * NOTE: This screen is fully self-contained (client-side only). Unlike spf.js it
 * does not call the backend — every outcome is pre-authored in the `scenarios`
 * dataset below so demos are 100% reliable with no network dependency.
 */

// ─────────────────────────────────────────────────────────────
// SCENARIO DATASET — the scripted stories shown as tabs
// ─────────────────────────────────────────────────────────────
// Each object is one teaching case. Key fields:
//   domain/attackerIP/record — the "email snapshot" shown to the user
//   softResult / hardResult   — the verdict under ~all vs -all (the whole point)
//   softSteps / hardSteps     — the animated step-by-step trace per policy
//   why / final               — plain-English explanation + headline verdict
//   *Banner                   — what the recipient's inbox would show
// TECH: softSteps/hardSteps mirror buildTimelineSteps() in spfRoutes.js.
// ─────────────────────────────────────────────
const scenarios = [
  {
    key: 'approved',
    label: 'Approved email server',
    tag: '✅ Pass',
    domain: 'company.com',
    attackerIP: '203.0.113.10',
    description: 'An authorised mail server that should pass SPF cleanly.',
    record: 'v=spf1 ip4:203.0.113.10 -all',
    why: 'The sending IP is listed in the SPF record, so this message passes SPF.',
    final: 'PASS — authorised sender recognised.',
    softResult: 'pass',
    hardResult: 'pass',
    softSteps: [
      { title: 'Sender IP matches', sub: 'The IP is explicitly allowed.', dot: 'pass' },
      { title: 'Policy outcome', sub: 'The sender is accepted under soft policy.', dot: 'pass' }
    ],
    hardSteps: [
      { title: 'Sender IP matches', sub: 'The IP is explicitly allowed.', dot: 'pass' },
      { title: 'Policy outcome', sub: 'The sender is accepted under strict policy.', dot: 'pass' }
    ],
    softBanner: 'Delivered to inbox',
    hardBanner: 'Accepted for delivery',
    matchedMechanism: 'ip4:203.0.113.10'
  },
  {
    key: 'unauthorised',
    label: 'Unauthorised server',
    tag: '❌ Fail',
    domain: 'company.com',
    attackerIP: '198.51.100.22',
    description: 'An unknown server that should fail SPF.',
    record: 'v=spf1 ip4:203.0.113.10 -all',
    why: 'The sending IP is not on the approved list, so SPF rejects it.',
    final: 'FAIL — unauthorised sender.',
    softResult: 'fail',
    hardResult: 'fail',
    softSteps: [
      { title: 'IP lookup', sub: 'The sender IP is not approved.', dot: 'fail' },
      { title: 'Policy outcome', sub: 'The message fails SPF.', dot: 'fail' }
    ],
    hardSteps: [
      { title: 'IP lookup', sub: 'The sender IP is not approved.', dot: 'fail' },
      { title: 'Policy outcome', sub: 'The message is rejected outright.', dot: 'fail' }
    ],
    softBanner: 'Warning shown in inbox',
    hardBanner: 'Rejected before delivery',
    matchedMechanism: 'none'
  },
  {
    key: 'spoofed',
    label: 'Spoofed sender',
    tag: '🎭 Spoof',
    domain: 'company.com',
    attackerIP: '185.220.101.5',
    description: 'A fake executive message that looks convincing.',
    record: 'v=spf1 ip4:203.0.113.10 ~all',
    why: 'The message appears to come from the company, but the server is not approved.',
    final: 'SOFTFAIL — suspicious and likely flagged.',
    softResult: 'softfail',
    hardResult: 'fail',
    softSteps: [
      { title: 'IP mismatch', sub: 'The message uses an unapproved IP.', dot: 'warn' },
      { title: 'Soft policy', sub: 'The message is treated as suspicious.', dot: 'warn' }
    ],
    hardSteps: [
      { title: 'IP mismatch', sub: 'The message uses an unapproved IP.', dot: 'fail' },
      { title: 'Hard policy', sub: 'The message is rejected.', dot: 'fail' }
    ],
    softBanner: 'Warning banner shown',
    hardBanner: 'Rejected before delivery',
    matchedMechanism: 'none'
  },
  {
    key: 'third-party',
    label: 'Third-party email service',
    tag: '📨 Trusted partner',
    domain: 'company.com',
    attackerIP: '209.85.220.41',
    description: 'A legitimate message from Google Workspace through a third-party service.',
    record: 'v=spf1 include:_spf.google.com -all',
    why: 'SPF trusts Google’s approved servers through the include mechanism.',
    final: 'PASS — trusted third-party sender.',
    softResult: 'pass',
    hardResult: 'pass',
    softSteps: [
      { title: 'Include lookup', sub: 'The include record points to Google’s SPF.', dot: 'pass' },
      { title: 'Policy outcome', sub: 'The sender is accepted.', dot: 'pass' }
    ],
    hardSteps: [
      { title: 'Include lookup', sub: 'The include record points to Google’s SPF.', dot: 'pass' },
      { title: 'Policy outcome', sub: 'The sender is accepted.', dot: 'pass' }
    ],
    softBanner: 'Delivered normally',
    hardBanner: 'Accepted for delivery',
    matchedMechanism: 'include:_spf.google.com'
  },
  {
    key: 'missing',
    label: 'Missing SPF record',
    tag: '⚠ No policy',
    domain: 'company.com',
    attackerIP: '104.16.0.5',
    description: 'A domain with no SPF record published in DNS.',
    record: 'No SPF record published',
    why: 'There is no SPF record to compare, so the provider cannot verify the sender.',
    final: 'NEUTRAL — no SPF evidence.',
    softResult: 'none',
    hardResult: 'none',
    softSteps: [
      { title: 'No SPF published', sub: 'There is nothing for the receiver to check.', dot: 'info' },
      { title: 'Policy outcome', sub: 'The result is neutral.', dot: 'info' }
    ],
    hardSteps: [
      { title: 'No SPF published', sub: 'There is nothing for the receiver to check.', dot: 'info' },
      { title: 'Policy outcome', sub: 'The result is neutral.', dot: 'info' }
    ],
    softBanner: 'No SPF evidence',
    hardBanner: 'No SPF evidence',
    matchedMechanism: 'none'
  },
  {
    key: 'multiple',
    label: 'Multiple SPF records',
    tag: '⚠ Configuration issue',
    domain: 'company.com',
    attackerIP: '203.0.113.11',
    description: 'A domain with more than one SPF TXT record, which causes confusion.',
    record: 'Multiple SPF records found',
    why: 'Having more than one SPF record creates confusion and weakens the check.',
    final: 'FAIL — misconfigured SPF.',
    softResult: 'fail',
    hardResult: 'fail',
    softSteps: [
      { title: 'Duplicate SPF records', sub: 'The domain has more than one SPF policy.', dot: 'fail' },
      { title: 'Policy outcome', sub: 'The check is invalid and should be fixed.', dot: 'fail' }
    ],
    hardSteps: [
      { title: 'Duplicate SPF records', sub: 'The domain has more than one SPF policy.', dot: 'fail' },
      { title: 'Policy outcome', sub: 'The check is invalid and should be fixed.', dot: 'fail' }
    ],
    softBanner: 'Configuration issue',
    hardBanner: 'Configuration issue',
    matchedMechanism: 'none'
  },
  {
    key: 'forwarded',
    label: 'Forwarded email',
    tag: '📤 Forwarded',
    domain: 'company.com',
    attackerIP: '172.16.0.10',
    description: 'A message that has been forwarded and changes the visible path.',
    record: 'v=spf1 ip4:172.16.0.10 -all',
    why: 'Forwarding can change the visible path, so SPF may behave differently.',
    final: 'PASS or neutral depending on forwarding rules.',
    softResult: 'pass',
    hardResult: 'none',
    softSteps: [
      { title: 'Forwarded path', sub: 'The path changes after forwarding.', dot: 'pass' },
      { title: 'Policy outcome', sub: 'The sender may still be accepted.', dot: 'info' }
    ],
    hardSteps: [
      { title: 'Forwarded path', sub: 'The path changes after forwarding.', dot: 'info' },
      { title: 'Policy outcome', sub: 'The result may be neutral in some receivers.', dot: 'info' }
    ],
    softBanner: 'Forwarded message',
    hardBanner: 'Receiver-specific result',
    matchedMechanism: 'ip4:172.16.0.10'
  },
  {
    key: 'softfail',
    label: 'SoftFail (~all)',
    tag: '⚪ Soft fail',
    domain: 'company.com',
    attackerIP: '198.51.100.77',
    description: 'A message that fails SPF but is only marked suspicious.',
    record: 'v=spf1 ip4:203.0.113.10 ~all',
    why: 'The IP is not listed, but SPF only marks it as suspicious rather than hard rejecting it.',
    final: 'SOFTFAIL — monitor and investigate.',
    softResult: 'softfail',
    hardResult: 'fail',
    softSteps: [
      { title: 'Unapproved IP', sub: 'The sender IP is not trusted.', dot: 'warn' },
      { title: 'Soft policy', sub: 'The message is marked suspicious.', dot: 'warn' }
    ],
    hardSteps: [
      { title: 'Unapproved IP', sub: 'The sender IP is not trusted.', dot: 'fail' },
      { title: 'Hard policy', sub: 'The message is rejected.', dot: 'fail' }
    ],
    softBanner: 'Suspicious sender',
    hardBanner: 'Rejected before delivery',
    matchedMechanism: 'none'
  },
  {
    key: 'hardfail',
    label: 'HardFail (-all)',
    tag: '🔒 Strict',
    domain: 'company.com',
    attackerIP: '198.51.100.77',
    description: 'A message that fails SPF under a strict hard-fail policy.',
    record: 'v=spf1 ip4:203.0.113.10 -all',
    why: 'The IP is not listed and the policy explicitly rejects unknown senders.',
    final: 'FAIL — hard fail policy enforced.',
    softResult: 'fail',
    hardResult: 'fail',
    softSteps: [
      { title: 'Unapproved IP', sub: 'The sender IP is not trusted.', dot: 'fail' },
      { title: 'Strict outcome', sub: 'The sender is blocked.', dot: 'fail' }
    ],
    hardSteps: [
      { title: 'Unapproved IP', sub: 'The sender IP is not trusted.', dot: 'fail' },
      { title: 'Strict outcome', sub: 'The sender is blocked.', dot: 'fail' }
    ],
    softBanner: 'Blocked by policy',
    hardBanner: 'Blocked by policy',
    matchedMechanism: 'none'
  },
  {
    key: 'neutral',
    label: 'Neutral (?all)',
    tag: '⚪ Neutral',
    domain: 'company.com',
    attackerIP: '198.51.100.77',
    description: 'A policy that takes no action for unknown senders.',
    record: 'v=spf1 ip4:203.0.113.10 ?all',
    why: 'The policy says “take no action” for unknown senders, which is weak protection.',
    final: 'NEUTRAL — little enforcement.',
    softResult: 'none',
    hardResult: 'none',
    softSteps: [
      { title: 'Neutral policy', sub: 'The receiver takes no action.', dot: 'info' },
      { title: 'Policy outcome', sub: 'Spoofing protection stays weak.', dot: 'info' }
    ],
    hardSteps: [
      { title: 'Neutral policy', sub: 'The receiver takes no action.', dot: 'info' },
      { title: 'Policy outcome', sub: 'Spoofing protection stays weak.', dot: 'info' }
    ],
    softBanner: 'No enforcement',
    hardBanner: 'No enforcement',
    matchedMechanism: 'none'
  }
];

// ─────────────────────────────────────────────────────────────
// SPF "CHEAT SHEET" — clickable glossary of record tokens
// ─────────────────────────────────────────────────────────────
// Powers the "record breakdown" panel: each chip explains one piece of SPF
// syntax in one sentence — handy for onboarding a non-technical audience.
// TECH: Maps to parseSPFRecord() token types in server/services/spf.js.
// ─────────────────────────────────────────────
const recordChips = [
  { token: 'v=spf1', detail: 'This starts every SPF record and shows the version being used.' },
  { token: 'ip4', detail: 'Allows a specific IPv4 address or range to send mail.' },
  { token: 'ip6', detail: 'Allows a specific IPv6 address to send mail.' },
  { token: 'a', detail: 'Trusts hosts that resolve to the domain’s A record.' },
  { token: 'mx', detail: 'Trusts mail servers listed in the domain’s MX records.' },
  { token: 'include', detail: 'Pulls in another domain’s SPF rules for third-party senders.' },
  { token: 'exists', detail: 'Checks whether a domain or host exists.' },
  { token: 'ptr', detail: 'Uses reverse DNS lookups, though this is less common.' },
  { token: 'redirect', detail: 'Points to another SPF record to keep things tidy.' },
  { token: 'exp', detail: 'Displays an explanation when an SPF check fails.' },
  { token: 'all', detail: 'The catch-all rule for everything that has not matched yet.' },
  { token: '(Pass)', detail: 'If a mechanism matches, the mail passes this check.' },
  { token: '(Fail)', detail: 'If a mechanism fails, the message is treated as unauthorised.' },
  { token: '~', detail: 'SoftFail marks a message as suspicious but not always rejected.' },
  { token: '?', detail: 'Neutral means “take no action” for this match.' }
];

// DOM references — keeps render functions readable during live demos/cache every element we update, so render functions stay fast.
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
  insight: document.getElementById('insight-text')
};

// UI state: which scenario tab and which glossary chip are currently selected.
let activeScenario = 0;
let activeChip = recordChips[0].token;

// Escape user/data text before injecting into innerHTML — prevents markup breakage/XSS.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Build the row of scenario tabs and wire each one to switch the active story.
/** Render scenario tab buttons; active tab drives populateInputs(). */
function renderScenarioTabs() {
  nodes.scenarioTabs.innerHTML = scenarios.map((scenario, index) => `
    <button class="scenario-tab ${index === activeScenario ? 'active' : ''}" data-index="${index}">
      <span class="scenario-name">${scenario.label}</span>
      <span class="scenario-tag">${scenario.tag}</span>
    </button>
  `).join('');

  nodes.scenarioTabs.querySelectorAll('.scenario-tab').forEach((button) => {
    button.addEventListener('click', () => {
      activeScenario = Number(button.dataset.index);
      renderScenarioTabs();
      populateInputs(scenarios[activeScenario]);
    });
  });
}

// Load a scenario into the input fields and refresh the whole simulation view.
function populateInputs(scenario) {
  nodes.targetDomain.value = scenario.domain;
  nodes.attackerIP.value = scenario.attackerIP;
  nodes.summary.textContent = scenario.description;
  renderSnapshot(scenario);
  renderSimulation();
}

// Show the "email under inspection" card (sender, MAIL FROM, IP, SPF record).
function renderSnapshot(scenario) {
  nodes.emailPreview.innerHTML = [
    row('Sender email', `sender@${scenario.domain}`),
    row('MAIL FROM domain', scenario.domain),
    row('Sending IP', scenario.attackerIP),
    row('SPF record', scenario.record)
  ].join('');

  nodes.spfResultBar.innerHTML = `
    <span class="spf-result-label">Sandbox status</span>
    <span class="spf-result-val">Ready to explore</span>
    <span class="spf-pill none">IDLE</span>
  `;
}

// Small helper: one label/value line inside the email snapshot card.
function row(label, value) {
  return `
    <div class="email-row">
      <span class="email-label">${escapeHtml(label)}</span>
      <span class="email-val">${escapeHtml(value)}</span>
    </div>
  `;
}

// ─────────────────────────────────────────────────────────────
// renderSimulation — the main "run" that paints the whole comparison
// ─────────────────────────────────────────────────────────────
// Renders the result bar, the soft vs hard step lists, both verdict boxes,
// the inbox/terminal views, and the closing "key insight" — the money shot
// that contrasts the two enforcement levels for the audience.
function renderSimulation() {
  const scenario = scenarios[activeScenario];

  nodes.summary.textContent = scenario.description;
  nodes.spfResultBar.innerHTML = `
    <span class="spf-result-label">Evaluation</span>
    <span class="spf-result-val">${escapeHtml(scenario.final)}</span>
    <span class="spf-pill ${resultClass(scenario.softResult)}">${escapeHtml(scenario.softResult.toUpperCase())}</span>
  `;

  renderSteps(nodes.softSteps, scenario.softSteps);
  renderSteps(nodes.hardSteps, scenario.hardSteps);

  const softMeta = verdictMeta(scenario.softResult, '~all');
  const hardMeta = verdictMeta(scenario.hardResult, '-all');
  renderVerdict(nodes.softVerdict, softMeta);
  renderVerdict(nodes.hardVerdict, hardMeta);

  nodes.softView.innerHTML = `
    <div class="client-shell">
      <div class="client-banner">${escapeHtml(scenario.softBanner)}</div>
      <div class="client-message">
        <strong>Inbox view</strong>
        <p>${escapeHtml(scenario.why)}</p>
      </div>
      <div class="client-meta">
        <span>From: sender@${escapeHtml(scenario.domain)}</span>
        <span>Status: ${escapeHtml(scenario.final)}</span>
      </div>
    </div>
  `;

  nodes.hardView.innerHTML = `
    <div class="terminal-shell">
      <div class="terminal-header">SMTP Log Terminal</div>
      <pre class="terminal-lines">[SMTP] Connecting to receiver\n[SPF] Evaluating domain ${escapeHtml(scenario.domain)}\n[SPF] Matched: ${escapeHtml(scenario.matchedMechanism)}\n[Result] ${escapeHtml(scenario.final)}</pre>
      <div class="terminal-${scenario.hardResult === 'pass' ? 'accept' : 'reject'}">${scenario.hardResult === 'pass' ? 'Accepted for delivery.' : 'Rejected before delivery.'}</div>
    </div>
  `;

  nodes.insight.innerHTML = `
    <div class="insight-grid">
      <div class="insight-box business">
        <div class="box-title">Why SPF passed or failed</div>
        <div class="box-body">${escapeHtml(scenario.why)}</div>
      </div>
      <div class="insight-box action">
        <div class="box-title">Final authentication result</div>
        <div class="box-body">${escapeHtml(scenario.final)}</div>
      </div>
    </div>
    <p class="explain-note">SPF is one layer of email authentication. DKIM checks the message itself, and DMARC decides what the receiver should do with the result.</p>
  `;
}

// Render an ordered list of trace steps with pass/fail/warn/info status dots.
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


// Map a result + policy to the final delivery verdict shown in the verdict box
// (delivered / delivered-with-warning / rejected) plus its icon and styling.
function verdictMeta(result, policy) {
  const normalized = String(result || '').toLowerCase();
  if (normalized === 'pass') {
    return { label: 'Delivered normally', detail: 'The sender is authorised and accepted.', icon: '✅', className: 'verdict-pass' };
  }
  if (normalized === 'softfail' || policy === '~all') {
    return { label: 'Delivered with warning', detail: 'The sender is suspicious but not fully rejected.', icon: '⚠️', className: 'verdict-warn' };
  }
  return { label: 'Rejected at SMTP layer', detail: 'The sender is not trusted and is blocked.', icon: '🚫', className: 'verdict-danger' };
}

// Paint one verdict box using the metadata produced by verdictMeta().
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

// Normalise an SPF result into the CSS class used for the coloured status pill.
function resultClass(result) {
  const normalized = String(result || '').toLowerCase();
  if (normalized === 'pass') return 'pass';
  if (normalized === 'softfail') return 'softfail';
  if (normalized === 'fail') return 'fail';
  return 'none';
}

// Build the clickable glossary chips and wire selection of each token.
function renderChips() {
  const grid = document.getElementById('chip-grid');
  grid.innerHTML = recordChips.map((chip) => `
    <button class="chip-btn ${chip.token === activeChip ? 'active' : ''}" data-token="${chip.token}">
      ${chip.token}
    </button>
  `).join('');

  grid.querySelectorAll('.chip-btn').forEach((button) => {
    button.addEventListener('click', () => {
      activeChip = button.dataset.token;
      renderChips();
      renderChipDetail();
    });
  });
}

// Show the one-line explanation for whichever glossary chip is selected.
function renderChipDetail() {
  const chip = recordChips.find((item) => item.token === activeChip) || recordChips[0];
  document.getElementById('chip-detail').innerHTML = `<strong>${chip.token}</strong> — ${chip.detail}`;
}

// Highlight the in-page nav link for whichever section is currently on screen.
// Only affects links with href="#..." (in-page anchors), not the top nav links.
function initNavHighlight() {
  const inPageLinks = Array.from(document.querySelectorAll('.site-nav ~ * .nav-link, .sub-nav .nav-link, [href^="#"].nav-link'));
  const allNavLinks = Array.from(document.querySelectorAll('.nav-link'));
  // Only target in-page anchor links, not top bar nav links (which have file hrefs)
  const links = allNavLinks.filter(link => link.getAttribute('href') && link.getAttribute('href').startsWith('#'));
  const sections = Array.from(document.querySelectorAll('section[id]'));
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        links.forEach((link) => link.classList.toggle('active', link.getAttribute('href') === `#${entry.target.id}`));
      }
    });
  }, { threshold: 0.35 });
  sections.forEach((section) => observer.observe(section));
}

// Optional knowledge-check quiz: gives instant right/wrong feedback per answer.
function initQuiz() {
  document.querySelectorAll('.quiz-question').forEach((question) => {
    const buttons = question.querySelectorAll('.quiz-btn');
    const feedback = question.querySelector('.quiz-feedback');
    buttons.forEach((button) => {
      button.addEventListener('click', () => {
        buttons.forEach((btn) => btn.classList.remove('active'));
        button.classList.add('active');
        const answer = question.querySelector('.quiz-options').dataset.answer;
        feedback.textContent = button.dataset.value === answer
          ? 'Correct — that is the right idea.'
          : 'Not quite — try the other option.';
      });
    });
  });
}



// ─────────────────────────────────────────────────────────────
// EVENT WIRING + INITIAL RENDER (runs on page load)
// ─────────────────────────────────────────────────────────────
// "Run simulation" re-paints the current scenario; "Reset" restores its defaults.
nodes.runButton.addEventListener('click', () => {
  renderSimulation();
});

nodes.resetButton.addEventListener('click', () => {
  populateInputs(scenarios[activeScenario]);
});

// Bootstrap the page: tabs → load first scenario → glossary → scroll-spy nav.
renderScenarioTabs();
populateInputs(scenarios[activeScenario]);
renderChips();
renderChipDetail();
initNavHighlight();