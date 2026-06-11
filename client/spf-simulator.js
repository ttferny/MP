/**
 * spf-simulator.js — SPF Softfail vs Hardfail Simulator
 * Tiffany's deliverable.
 *
 * WHAT THIS DOES:
 * ---------------
 * Shows the same email being processed under ~all (softfail)
 * and -all (hardfail) policies side by side.
 *
 * Each scenario has a pre-built email, SPF result, and
 * step-by-step pipeline for both policies.
 *
 * No backend needed — runs entirely in the browser.
 * Demonstrates SPF policy evaluation logic visually.
 */

// ── Scenario definitions ───────────────────────────────────
const SCENARIOS = [
  {
    label:   '🎭 Spoofed CEO email',
    tag:     'BEC Attack',
    email: {
      from:       'ceo@company.com',
      returnPath: 'ceo@attacker.com',
      senderIP:   '185.220.101.5',
      subject:    'Urgent: Wire transfer needed immediately',
      note:       'IP 185.220.101.5 is not in company.com SPF record',
    },
    spfCheck: 'fail',
    spfReason: 'IP 185.220.101.5 not authorised for company.com — matched -all / ~all',
    soft: {
      steps: [
        { dot: 'fail', title: 'SPF check fails',            sub: 'Sender IP 185.220.101.5 is not in company.com\'s approved list' },
        { dot: 'warn', title: '~all triggers soft fail',    sub: 'Policy says "mark as suspicious but still deliver"' },
        { dot: 'warn', title: 'Email tagged with spf=softfail', sub: 'An X-header is added but the email continues delivery' },
        { dot: 'warn', title: 'Delivered to inbox or spam', sub: 'The receiving server decides — many deliver it to inbox' },
      ],
      verdict: 'warn',
      label:  '⚠ Delivered — attack may succeed',
      detail: 'Soft fail does not stop the spoofed CEO email. The recipient could be tricked into transferring money.',
    },
    hard: {
      steps: [
        { dot: 'fail', title: 'SPF check fails',              sub: 'Sender IP 185.220.101.5 is not in company.com\'s approved list' },
        { dot: 'fail', title: '-all triggers hard fail',      sub: 'Policy says "reject this message"' },
        { dot: 'fail', title: 'Server returns 550 rejection', sub: 'SMTP error sent back to the attacker\'s server' },
        { dot: 'pass', title: 'Attack blocked entirely',      sub: 'The email never reaches the recipient\'s inbox' },
      ],
      verdict: 'danger',
      label:  '🚫 Rejected — attack blocked',
      detail: 'Hard fail stops the spoofed email at the server level before anyone sees it.',
    },
    insight: '<strong>This is Business Email Compromise (BEC)</strong> — one of the most costly cyberattacks. With <strong>~all</strong>, the spoofed CEO email still reaches the inbox and the finance team may wire money to the attacker. With <strong>-all</strong>, the email is rejected immediately and the attack fails. This scenario alone is why security experts recommend -all.',
  },

  {
    label:   '🏦 Banking phishing',
    tag:     'Phishing Attack',
    email: {
      from:       'security@dbs.com',
      returnPath: 'noreply@phish-server.ru',
      senderIP:   '45.33.32.156',
      subject:    'Your account has been compromised — verify now',
      note:       'Sending domain dbs.com has p=reject DMARC and strict SPF',
    },
    spfCheck: 'fail',
    spfReason: 'IP 45.33.32.156 not authorised for dbs.com — attacker\'s server',
    soft: {
      steps: [
        { dot: 'fail', title: 'SPF check fails',              sub: 'Attacker\'s IP not in dbs.com SPF record' },
        { dot: 'warn', title: '~all: soft fail triggered',    sub: 'Email tagged as suspicious but not blocked' },
        { dot: 'warn', title: 'Email may reach spam folder',  sub: 'Some servers deliver it, some quarantine it' },
        { dot: 'warn', title: 'Victim could still click link',sub: 'Phishing link in email still accessible if delivered' },
      ],
      verdict: 'warn',
      label:  '⚠ Possibly delivered to spam',
      detail: 'Soft fail gives the phishing email a chance — it may land in spam or even inbox depending on the mail server.',
    },
    hard: {
      steps: [
        { dot: 'fail', title: 'SPF check fails',              sub: 'Attacker\'s IP not in dbs.com SPF record' },
        { dot: 'fail', title: '-all: hard fail triggered',    sub: 'Policy clearly states: reject unauthorised senders' },
        { dot: 'fail', title: 'Email rejected at gateway',    sub: 'Mail server refuses to accept the message' },
        { dot: 'pass', title: 'Phishing attempt blocked',     sub: 'Victim never receives the email — attack fails' },
      ],
      verdict: 'danger',
      label:  '🚫 Rejected — phishing blocked',
      detail: 'Hard fail stops the phishing email before it reaches anyone. The victim never sees the fake bank login link.',
    },
    insight: '<strong>Phishing attacks impersonating banks</strong> rely on reaching the victim\'s inbox. With <strong>~all</strong>, the email has a chance of delivery — even in spam, curious users may open it. With <strong>-all</strong>, the email is rejected at the gateway and the victim is protected without ever knowing the attack happened.',
  },

  {
    label:   '✅ Legitimate newsletter',
    tag:     'Authorised sender',
    email: {
      from:       'newsletter@company.com',
      returnPath: 'newsletter@company.com',
      senderIP:   '167.89.0.1',
      subject:    'Your monthly update from Company',
      note:       'IP 167.89.0.1 is in company.com SPF via include:sendgrid.net',
    },
    spfCheck: 'pass',
    spfReason: 'IP 167.89.0.1 matched include:sendgrid.net — authorised sender',
    soft: {
      steps: [
        { dot: 'pass', title: 'SPF check passes',          sub: 'Sender IP matches include:sendgrid.net in the SPF record' },
        { dot: 'pass', title: '~all does not apply',       sub: 'Policy only affects failures — this email passed' },
        { dot: 'pass', title: 'Email delivered normally',  sub: 'No suspicious flags added' },
      ],
      verdict: 'pass',
      label:  '✅ Delivered normally',
      detail: 'Legitimate email is unaffected by ~all — the policy only kicks in on failures.',
    },
    hard: {
      steps: [
        { dot: 'pass', title: 'SPF check passes',          sub: 'Sender IP matches include:sendgrid.net in the SPF record' },
        { dot: 'pass', title: '-all does not apply',       sub: 'Policy only affects failures — this email passed' },
        { dot: 'pass', title: 'Email delivered normally',  sub: 'No suspicious flags added' },
      ],
      verdict: 'pass',
      label:  '✅ Delivered normally',
      detail: 'Legitimate email is unaffected by -all — the policy only kicks in on failures.',
    },
    insight: '<strong>Key takeaway:</strong> Both <strong>~all</strong> and <strong>-all</strong> behave identically for legitimate emails that pass SPF. Switching from ~all to -all will <em>not</em> break your real mail — it only blocks unauthorised senders. This means there is no downside to using -all once your SPF record is correct.',
  },

  {
    label:   '⚠ No SPF record',
    tag:     'Misconfigured domain',
    email: {
      from:       'support@vulnerable.org',
      returnPath: 'noreply@attacker.com',
      senderIP:   '104.21.0.99',
      subject:    'Your account requires immediate action',
      note:       'vulnerable.org has no SPF record published in DNS',
    },
    spfCheck: 'none',
    spfReason: 'No SPF record found for vulnerable.org — result is "none"',
    soft: {
      steps: [
        { dot: 'info', title: 'DNS lookup: no SPF record',   sub: 'vulnerable.org has not published an SPF record' },
        { dot: 'info', title: 'SPF result: none',            sub: '~all cannot apply — there is no policy to enforce' },
        { dot: 'warn', title: 'Email delivered anyway',      sub: 'No basis to reject or flag it' },
        { dot: 'warn', title: 'DMARC may still help',        sub: 'If DMARC is configured separately, it can still act' },
      ],
      verdict: 'warn',
      label:  '⚠ Delivered — no SPF protection',
      detail: '~all is meaningless without an SPF record. The policy does not exist so it cannot be applied.',
    },
    hard: {
      steps: [
        { dot: 'info', title: 'DNS lookup: no SPF record',   sub: 'vulnerable.org has not published an SPF record' },
        { dot: 'info', title: 'SPF result: none',            sub: '-all cannot apply — there is no policy to enforce' },
        { dot: 'warn', title: 'Email delivered anyway',      sub: 'No basis to reject or flag it' },
        { dot: 'warn', title: 'DMARC may still help',        sub: 'If DMARC is configured separately, it can still act' },
      ],
      verdict: 'warn',
      label:  '⚠ Delivered — no SPF protection',
      detail: '-all is meaningless without an SPF record. You must publish an SPF record first before any policy can take effect.',
    },
    insight: '<strong>Having no SPF record</strong> means neither ~all nor -all can help — there is nothing to enforce. This is one of the most common real-world misconfigurations. An attacker can spoof any domain with no SPF record and the email will be delivered. The fix is simple: publish an SPF record. Use the <a href="spf-builder.html">SPF Builder</a> to generate one.',
  },

  {
    label:   '🔀 SPF pass, misaligned',
    tag:     'DMARC alignment failure',
    email: {
      from:       'ceo@company.com',
      returnPath: 'ceo@attacker.com',
      senderIP:   '192.168.1.10',
      subject:    'Invoice payment approval required',
      note:       'SPF passes for attacker.com but From shows company.com — misalignment',
    },
    spfCheck: 'pass',
    spfReason: 'IP 192.168.1.10 authorised for attacker.com — but not company.com',
    soft: {
      steps: [
        { dot: 'pass', title: 'SPF check passes',              sub: 'IP is authorised — but for attacker.com, not company.com' },
        { dot: 'warn', title: 'DMARC alignment fails',         sub: 'SPF domain (attacker.com) does not align with From (company.com)' },
        { dot: 'warn', title: '~all: soft fail on alignment',  sub: 'Email tagged but may still be delivered' },
        { dot: 'warn', title: 'Attack partially succeeds',     sub: 'Without strict DMARC, this email may reach the inbox' },
      ],
      verdict: 'warn',
      label:  '⚠ May be delivered — alignment gap',
      detail: 'SPF passes but for the wrong domain. ~all alone cannot catch this — DMARC alignment checking is what prevents it.',
    },
    hard: {
      steps: [
        { dot: 'pass', title: 'SPF check passes',              sub: 'IP is authorised — but for attacker.com, not company.com' },
        { dot: 'fail', title: 'DMARC alignment fails',         sub: 'SPF domain (attacker.com) does not align with From (company.com)' },
        { dot: 'fail', title: 'DMARC policy: reject',          sub: 'Even though SPF passed, DMARC catches the misalignment' },
        { dot: 'pass', title: 'Email rejected',                sub: 'Attack blocked by DMARC alignment — not SPF alone' },
      ],
      verdict: 'danger',
      label:  '🚫 Rejected by DMARC alignment',
      detail: 'This shows why DMARC is essential. SPF alone passed — DMARC alignment checking is what caught the attack.',
    },
    insight: '<strong>This is the most important scenario.</strong> SPF passed — but for the attacker\'s domain, not the visible From domain. Without DMARC alignment checking, <strong>both ~all and -all would let this through</strong>. DMARC is what closes this gap by requiring the SPF domain to align with the From header. This is exactly why SPF, DKIM, and DMARC must all work together.',
  },
];

// ── State ──────────────────────────────────────────────────
let current = 0;

// ── Build scenario tab buttons ─────────────────────────────
function renderTabs() {
  const container = document.getElementById('scenario-tabs');
  container.innerHTML = SCENARIOS.map((s, i) => `
    <button
      class="scenario-tab${i === current ? ' active' : ''}"
      onclick="selectScenario(${i})"
    >
      ${s.label}
      <span class="scenario-tag">${s.tag}</span>
    </button>
  `).join('');
}

function selectScenario(i) {
  current = i;
  renderTabs();
  renderAll();
}

// ── Render email preview ───────────────────────────────────
function renderEmail(s) {
  const fromDomain     = s.email.from.split('@')[1];
  const returnDomain   = s.email.returnPath.split('@')[1];
  const domainMismatch = fromDomain !== returnDomain;

  document.getElementById('email-preview').innerHTML = `
    ${emailRow('From',        s.email.from,       false)}
    ${emailRow('Return-Path', s.email.returnPath, domainMismatch)}
    ${emailRow('Sender IP',   s.email.senderIP,   false)}
    ${emailRow('Subject',     s.email.subject,    false)}
    ${emailRow('Note',        s.email.note,       true)}
  `;

  const pillCls = { pass: 'pass', fail: 'fail', none: 'none', softfail: 'softfail' }[s.spfCheck] || 'none';
  document.getElementById('spf-result-bar').innerHTML = `
    <span class="spf-result-label">SPF result</span>
    <span class="spf-result-val">${escHtml(s.spfReason)}</span>
    <span class="spf-pill ${pillCls}">${s.spfCheck.toUpperCase()}</span>
  `;
}

function emailRow(label, val, flagged) {
  return `
    <div class="email-row">
      <span class="email-label">${label}</span>
      <span class="email-val${flagged ? ' flagged' : ''}">${escHtml(val)}</span>
    </div>
  `;
}

// ── Render one pipeline side ───────────────────────────────
function renderPipeline(stepsId, verdictId, data) {
  // Steps
  document.getElementById(stepsId).innerHTML = data.steps.map(st => `
    <div class="step-row">
      <div class="step-dot dot-${st.dot}">${dotSymbol(st.dot)}</div>
      <div>
        <div class="step-title">${escHtml(st.title)}</div>
        <div class="step-sub">${escHtml(st.sub)}</div>
      </div>
    </div>
  `).join('');

  // Verdict
  const clsMap = { pass: 'verdict-pass', warn: 'verdict-warn', danger: 'verdict-danger' };
  document.getElementById(verdictId).className = `verdict-box ${clsMap[data.verdict] || 'verdict-warn'}`;
  document.getElementById(verdictId).innerHTML = `
    <span class="verdict-icon">${verdictIcon(data.verdict)}</span>
    <div>
      <div class="verdict-label">${escHtml(data.label)}</div>
      <div class="verdict-detail">${escHtml(data.detail)}</div>
    </div>
  `;
}

// ── Render insight ─────────────────────────────────────────
function renderInsight(s) {
  document.getElementById('insight-text').innerHTML = s.insight;
}

// ── Render everything ──────────────────────────────────────
function renderAll() {
  const s = SCENARIOS[current];
  renderEmail(s);
  renderPipeline('steps-soft', 'verdict-soft', s.soft);
  renderPipeline('steps-hard', 'verdict-hard', s.hard);
  renderInsight(s);
}

// ── Helpers ────────────────────────────────────────────────
function dotSymbol(type) {
  return { pass: '✓', fail: '✕', warn: '!', info: 'i' }[type] || 'i';
}

function verdictIcon(type) {
  return { pass: '✅', warn: '⚠️', danger: '🚫' }[type] || '⚠️';
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Init ───────────────────────────────────────────────────
renderTabs();
renderAll();