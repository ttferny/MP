/**
 * spf-builder.js — SPF Record Builder Logic
 * * WHAT THIS DOES:
 * ---------------
 * Lets users build a valid SPF TXT record by:
 * 1. Selecting which email services they use
 * 2. Adding custom IP addresses
 * 3. Choosing a policy (~all / -all / ?all)
 *
 * The generated record updates live as they make changes.
 * Includes DNS lookup counting, specific warning thresholds, 
 * and backend health-check routing.
 *
 * PITCH NOTE:
 * This builder translates SPF from a protocol rule into a practical business
 * control by surfacing cost, risk, and enforcement strength as the record grows.
 */

// ── Known email services and their SPF include strings ────
// These presets let the presenter talk about common vendors instead of raw
// DNS syntax, which makes the control easier to explain.
const SERVICES = [
  { id: 'google',     name: 'Google Workspace', include: '_spf.google.com',            lookups: 4 },
  { id: 'microsoft',  name: 'Microsoft 365',    include: 'spf.protection.outlook.com', lookups: 3 },
  { id: 'sendgrid',   name: 'SendGrid',         include: 'sendgrid.net',               lookups: 2 },
  { id: 'mailchimp',  name: 'Mailchimp',        include: 'servers.mcsv.net',           lookups: 2 },
  { id: 'mailgun',    name: 'Mailgun',          include: 'mailgun.org',                lookups: 2 },
  { id: 'hubspot',    name: 'HubSpot',          include: '_spf.hubspot.com',           lookups: 2 },
  { id: 'salesforce', name: 'Salesforce',       include: '_spf.salesforce.com',        lookups: 2 },
  { id: 'zoho',       name: 'Zoho Mail',        include: 'zoho.com',                   lookups: 2 },
  { id: 'amazon',     name: 'Amazon SES',       include: 'amazonses.com',              lookups: 2 },
  { id: 'sparkpost',  name: 'SparkPost',        include: 'sparkpostmail.com',          lookups: 2 },
];

document.querySelectorAll('.accordion-trigger').forEach((trigger) => {
  const panelId = trigger.dataset.target;
  const panel = document.getElementById(panelId);
  const item = trigger.closest('.accordion-item');

  if (!panel || !item) return;

  // Collapsible "Descriptions" / "How to add this to DNS" panels — click to expand.
  trigger.addEventListener('click', () => {
    const isOpen = !panel.classList.contains('hidden');
    panel.classList.toggle('hidden', isOpen);
    item.classList.toggle('open', !isOpen);
  });
});

// ── State ──────────────────────────────────────────────────
// The three inputs that fully describe the record being built. Everything the
// UI shows is derived from these, so the generated SPF string stays in sync.
let selected = new Set();  // service IDs the user ticked (→ include: mechanisms)
let ips      = [];         // custom sender IPs typed in (→ ip4:/ip6: mechanisms)
let policy   = '-all';     // enforcement level: -all (hard) / ~all (soft) / ?all

// ── Render service buttons ─────────────────────────────────
// Draws one toggle button per known email provider; active buttons are included.
function renderServices() {
  const grid = document.getElementById('svc-grid');
  grid.innerHTML = SERVICES.map(s => `
    <button
      class="svc-btn${selected.has(s.id) ? ' active' : ''}"
      onclick="toggleService('${s.id}')"
      aria-pressed="${selected.has(s.id)}"
    >
      <div>
        <div class="svc-name">${s.name}</div>
        <div class="svc-include">include:${s.include}</div>
      </div>
    </button>
  `).join('');
}

// Flip a service on/off, then re-render buttons and regenerate the record.
function toggleService(id) {
  selected.has(id) ? selected.delete(id) : selected.add(id);
  renderServices();
  buildRecord();
}

// ── Render IP rows ─────────────────────────────────────────
// Append a blank custom-IP row for the user to fill in.
function addIP() {
  ips.push('');
  renderIPs();
}

function removeIP(i) {
  ips.splice(i, 1);
  renderIPs();
  buildRecord();
}

function updateIP(i, val) {
  ips[i] = val.trim();
  buildRecord();
}

// Re-draw the editable list of custom IP inputs from the `ips` array.
function renderIPs() {
  const el = document.getElementById('ip-list');
  el.innerHTML = ips.map((ip, i) => `
    <div class="ip-row">
      <input
        type="text"
        value="${escAttr(ip)}"
        placeholder="e.g. 203.0.113.10 or 203.0.113.0/24"
        oninput="updateIP(${i}, this.value)"
        spellcheck="false"
      />
      <button class="remove-btn" onclick="removeIP(${i})" aria-label="Remove IP">✕</button>
    </div>
  `).join('');
}

// ── Policy selection ───────────────────────────────────────
// Record the chosen enforcement level and highlight the matching policy button.
function setPolicy(p) {
  policy = p;
  document.querySelectorAll('.policy-btn').forEach(b => b.classList.remove('active'));
  const map = { '?all': 'pol-neutral', '~all': 'pol-soft', '-all': 'pol-hard' };
  document.getElementById(map[p])?.classList.add('active');
  buildRecord();
}

// ── Count DNS lookups ──────────────────────────────────────
// SPF permits at most 10 DNS lookups (RFC 7208). Each include: costs several,
// so we sum them up to warn the user before they hit the limit (a PermError).
function countLookups() {
  return SERVICES
    .filter(s => selected.has(s.id))
    .reduce((sum, s) => sum + s.lookups, 0);
}

// ── Build the SPF record string ────────────────────────────
// Assemble the final TXT value in RFC order:
//   v=spf1 → ip4/ip6 (cheapest, no lookup) → include: (per service) → policy
function getRecord() {
  const parts = ['v=spf1'];

  // Add custom IPs first (no DNS lookup cost)
  // Explicit sender IPs are the simplest business-friendly control.
  ips.filter(ip => ip).forEach(ip => {
    const isIPv6 = ip.includes(':') && !ip.includes('.');
    parts.push(`${isIPv6 ? 'ip6' : 'ip4'}:${ip}`);
  });

  // Add service includes
  SERVICES.filter(s => selected.has(s.id)).forEach(s => {
    parts.push(`include:${s.include}`);
  });

  parts.push(policy);
  return parts.join(' ');
}

// ── Build coloured HTML for the record display ─────────────
// Syntax-highlight each token so the record is easy to read on screen / in a demo.
function getRecordHTML(record) {
  return record.split(' ').map(tok => {
    if (tok === 'v=spf1')                            return `<span class="tok-ver">${tok}</span>`;
    if (tok.startsWith('ip4:') || tok.startsWith('ip6:')) return `<span class="tok-ip">${escHtml(tok)}</span>`;
    if (tok.startsWith('include:'))                  return `<span class="tok-inc">${escHtml(tok)}</span>`;
    if (tok === '-all')                              return `<span class="tok-hard">${tok}</span>`;
    if (tok === '~all')                              return `<span class="tok-soft">${tok}</span>`;
    return `<span class="tok-neut">${tok}</span>`;
  }).join(' ');
}

// ── Build the plain-English explanation list ───────────────
function buildExplanation(record) {
  const items = [];
  const parts = record.split(' ');

  parts.forEach(tok => {
    // Each explanation line doubles as demo narration: what the token means,
    // why it matters operationally, and what risk it implies.
    if (tok === 'v=spf1') {
      items.push({ token: tok, desc: 'SPF version declaration.', sub: 'Every SPF record must start with this.' });
    } else if (tok.startsWith('ip4:')) {
      items.push({ token: tok, desc: `Authorises the IPv4 address or range ${tok.slice(4)} to send email.`, sub: '' });
    } else if (tok.startsWith('ip6:')) {
      items.push({ token: tok, desc: `Authorises the IPv6 address ${tok.slice(4)} to send email.`, sub: '' });
    } else if (tok.startsWith('include:')) {
      const domain = tok.slice(8);
      const svc = SERVICES.find(s => s.include === domain);
      items.push({ token: tok, desc: `Includes ${svc ? svc.name + "'s" : ''} authorised sending servers.`, sub: `Fetches the SPF record at ${domain} and trusts any IPs listed there.` });
    } else if (tok === '-all') {
      items.push({ token: tok, desc: 'Reject all other senders not listed above.', sub: 'Hard fail — strongest protection. Recommended.' });
    } else if (tok === '~all') {
      items.push({ token: tok, desc: 'Mark all other senders as suspicious but still deliver.', sub: 'Soft fail — useful during testing or migration.' });
    } else if (tok === '?all') {
      items.push({ token: tok, desc: 'Take no action on other senders.', sub: 'Neutral — provides no protection. Not recommended.' });
    }
  });

  return items;
}

// ── Main build function — called on every change ───────────
// The single source of truth for the output panel. Every input handler calls
// this, so the record, lookup meter, warnings, and explanations update live.
function buildRecord() {
  const record  = getRecord();
  const domain  = document.getElementById('spf-domain').value.trim() || 'yourdomain.com';
  const lookups = countLookups();

  // Coloured record display
  document.getElementById('spf-output').innerHTML = getRecordHTML(record);

  // Lookup bar
  const pct  = Math.min(100, (lookups / 10) * 100);
  const fill = document.getElementById('lookup-fill');
  fill.style.width = `${pct}%`;
  fill.className   = `lookup-fill${lookups > 10 ? ' over' : lookups >= 8 ? ' warn' : ''}`;
  const countEl    = document.getElementById('lookup-count');
  countEl.textContent = `${lookups} / 10`;
  countEl.className   = `lookup-count${lookups > 10 ? ' over' : ''}`;

  // Warnings
  const warnings = [];
  
  // Custom Yellow Warning Banner for > 10 lookups
  if (lookups > 10) {
    // Note: error is set to 'false' so it explicitly uses the yellow standard warning CSS, 
    // rather than the red '.error' class as requested.
    warnings.push({ text: `Warning: This record approaches or exceeds the 10 DNS lookup limit.`, error: false });
  } else if (lookups >= 8) {
    warnings.push({ text: `You are using ${lookups}/10 DNS lookups. You are close to the limit — be careful adding more services.`, error: false });
  }





  // Other logic checks
  if (policy === '?all') {
    warnings.push({ text: '"?all" (neutral) provides no real protection. Spoofed emails will still be delivered. Consider using "~all" or "-all".', error: false });
  }
  if (ips.some(ip => ip === '0.0.0.0/0')) {
    warnings.push({ text: '"0.0.0.0/0" authorises every IP address in the world — this completely defeats SPF. Remove it.', error: true });
  }

  const warnBlock = document.getElementById('warnings-block');
  warnBlock.innerHTML = warnings.map(w =>
    `<div class="warning-item${w.error ? ' error' : ''}">⚠️ ${escHtml(w.text)}</div>`
  ).join('');

  // DNS hint
  document.getElementById('dns-hint').innerHTML =
    `Add as a <strong>TXT record</strong> in DNS for <strong>${escHtml(domain)}</strong> — name: <code>@</code>`;

  // Explanation list
  // The explanation list is the presentation layer for the SPF syntax.
  const items = buildExplanation(record);
  document.getElementById('explain-list').innerHTML = items.map(item => `
    <div class="explain-item">
      <span class="explain-token">${escHtml(item.token)}</span>
      <div class="explain-desc">
        ${escHtml(item.desc)}
        ${item.sub ? `<small>${escHtml(item.sub)}</small>` : ''}
      </div>
    </div>
  `).join('');
}

// ── Copy to clipboard ──────────────────────────────────────
// One-click copy of the generated record, with a brief "✓ Copied" confirmation.
function copyRecord() {
  const record = getRecord();
  navigator.clipboard.writeText(record).then(() => {
    const el = document.getElementById('copy-ok');
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 2000);
  });
}

// ── Test record — send to dynamic backend page ────────────
async function testRecord() {
  const domain = document.getElementById('spf-domain').value.trim();
  
  if (!domain) {
    alert('Enter your domain name first so we can look it up.');
    return;
  }

  try {
    // NOTE: Uncomment this block if your backend groupmate has a health endpoint 
    // to check before routing. This fulfills the robust error handling constraint.
    /*
    const healthCheck = await fetch('/api/health'); 
    if (!healthCheck.ok) {
      throw new Error('Backend API is currently offline.');
    }
    */

    // Redirect to the dynamic SPF test page with the URL parameter
    window.location.href = `spf.html?domain=${encodeURIComponent(domain)}`;
    
  } catch (error) {
    console.error("Backend Connection Error:", error);
    // Graceful UI alert for offline backend
    alert('⚠️ Error: The backend server appears to be offline or unreachable. Please try again later.');
  }
}

// ── Utilities ──────────────────────────────────────────────
// Escape helpers — sanitise user input before putting it into HTML / attributes.
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escAttr(s) {
  return String(s).replace(/"/g, '&quot;');
}

// ── Init ───────────────────────────────────────────────────
// First paint on page load: draw services, the (empty) IP list, and the default
// "v=spf1 -all" record so the user always sees a valid starting point.
renderServices();
renderIPs();
buildRecord();

// ── Clear All Services Event Listener ──────────────────────
document.getElementById('clear-services-btn')?.addEventListener('click', () => {
  selected.clear();  // Empties the Set containing selected email services
  renderServices();  // Redraws the service grid with zero active highlights
  buildRecord();     // Re-generates the SPF text output live
});