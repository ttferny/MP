// Scenario metadata for the frontend (icons, descriptions, attack info)
// The actual SPF/DKIM values and policy logic live in scenarioService.js on the backend
// Zircon
const scenarioMeta = {
  "legitimate":         { icon: "✅", name: "Legitimate Email",        defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "A real email from legitbank.com, sent from their authorised server with a valid DKIM signature.",                               attack: "No attack. This is the baseline — a genuine email that should always be delivered."                                                                             },
  "basic-spoof":        { icon: "❌", name: "Basic Spoofed Sender",    defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "An attacker sends an email pretending to be legitbank.com but from their own server with no valid signature.",                   attack: "Attacker sets From: legitbank.com but sends from evil.com. SPF and DKIM both fail alignment."                                                                   },
  "ceo-fraud":          { icon: "🎭", name: "CEO Fraud",               defaultPolicy: "quarantine", fromDomain: "company.com",      desc: "Attacker impersonates a company CEO to trick the finance team into transferring money.",                                         attack: "Attacker registers ceo-company.com (looks similar), passes SPF on that domain, but the From: shows ceo@company.com. DKIM is missing."                          },
  "banking-phish":      { icon: "🏦", name: "Banking Phishing",        defaultPolicy: "reject",     fromDomain: "dbs.com.sg",       desc: "Mass phishing campaign spoofing a bank to steal customer credentials via a fake login page.",                                    attack: "Attacker fully spoofs dbs.com.sg — forges the From: header. No valid SPF or DKIM for the real domain."                                                          },
  "monitor-only":       { icon: "👀", name: "Weak DMARC Policy",       defaultPolicy: "none",       fromDomain: "example.com",      desc: "The domain has DMARC set up but only in monitoring mode — a common misconfiguration.",                                          attack: "Same spoofed email as basic-spoof, but the domain owner set p=none meaning DMARC takes no action."                                                              },
  "spf-misalign":       { icon: "🔀", name: "SPF Pass, Misaligned",    defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "A subtle attack where SPF passes but on the wrong domain — exactly the gap DMARC was designed to close.",                       attack: "Attacker's server has a valid SPF record for evil.com. SPF passes. But the From: header shows legitbank.com. Without DMARC, this slips through."              },
  "strict-fail":        { icon: "🔒", name: "Strict Alignment Fail",   defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "Email sent from a subdomain mail.legitbank.com but DMARC is set to strict alignment.",                                          attack: "Not an attack — this shows how strict mode can break legitimate subdomain senders."                                                                             },
  "relaxed-pass":       { icon: "🔓", name: "Relaxed Alignment Pass",  defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "Same subdomain email but DMARC is set to relaxed alignment — the default.",                                                     attack: "Not an attack — shows how relaxed mode correctly allows legitimate subdomain senders."                                                                         },
  "forwarded-email":    { icon: "📧", name: "Forwarded Email",         defaultPolicy: "reject",     fromDomain: "example.com",      desc: "A legitimate email forwarded by a third-party service like Gmail, which changes the From: header.",                               attack: "Not an attack — shows a common legitimate scenario that DMARC can break."                                                                                     },
  "subdomain-spoof":    { icon: "🚨", name: "Subdomain Spoof Attack",  defaultPolicy: "reject",     fromDomain: "company.com",      desc: "Attacker creates a lookalike subdomain to bypass organizational domain checks.",                                                 attack: "Attacker registers newsletter.company.com and gets SPF to pass. From: is set to alerts@company.com."                                                           },
  "pct-50-pass":        { icon: "50️⃣", name: "Partial Enforcement (Pass)", defaultPolicy: "quarantine", fromDomain: "legitbank.com",    desc: "A legitimate email with p=quarantine pct=50. Only 50% of emails get the policy action.",                                     attack: "Not an attack — shows a gradual rollout strategy, but creates security gaps."                                                                                   },
  "pct-50-fail":        { icon: "⚠️", name: "Partial Enforcement (Fail)", defaultPolicy: "quarantine", fromDomain: "company.com",      desc: "Spoofed email with p=quarantine pct=50. Only 50% get quarantined, 50% slip through.",                                     attack: "Attacker sends spoofed email. With pct=50, roughly half bypass quarantine and reach inboxes."                                                                 },
  "subdomain-policy":   { icon: "🔗", name: "Subdomain Policy (sp=)",  defaultPolicy: "reject",     fromDomain: "mail.legitbank.com", desc: "Email from subdomain with sp=none (subdomain policy), main domain has p=reject.",                                               attack: "Not an attack — shows how sp= allows subdomains to have different policies."                                                                                   },
};

let currentScenario = null;

// Load scenario details into Step 2 panel
function loadScenario(key) {
  const s = scenarioMeta[key];
  if (!s) return;
  currentScenario = key;

  // Highlight selected card
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
  event.currentTarget.classList.add('active');

  // Fill detail panel
  document.getElementById("detail-icon").textContent   = s.icon;
  document.getElementById("detail-name").textContent   = s.name;
  document.getElementById("detail-desc").textContent   = s.desc;
  document.getElementById("detail-attack").textContent = s.attack;
  document.getElementById("dmarc-policy").value        = s.defaultPolicy;
  document.getElementById("from-domain").value = s.fromDomain;

  // Show detail card, hide result
  const detailCard = document.getElementById("scenario-detail");
  detailCard.style.display = "block";
  detailCard.style.animation = "none";
  void detailCard.offsetWidth;
  detailCard.style.animation = "fadeUp 0.4s ease both";

  document.getElementById("result").style.display = "none";
}

// Call backend: POST /api/dmarc/scenarios/:key
// Sends the selected policy and alignment modes so user can override scenario defaults
async function runDMARC() {

  if (!currentScenario) return;

  const policy = document.getElementById("dmarc-policy").value;
  const aspf = document.getElementById("aspf-mode").value;
  const adkim = document.getElementById("adkim-mode").value;
  const spEl = document.getElementById("sp-mode");
  const sp = spEl ? spEl.value || null : null;

  try {
    const response = await fetch(`/api/dmarc/scenarios/${currentScenario}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ policy, aspf, adkim, sp, log: true })

    });

    if (!response.ok) throw new Error("Server error: " + response.status);

    const result = await response.json();
    renderResult(result);

  } catch (err) {
    renderResult({
      status: "error",
      action: "none",
      reason: "Could not reach server. Make sure node app.js is running.",
      policy: "N/A",
      spfAligned: false,
      dkimAligned: false,
      explanation: ""
    });
  }
}

// Render the result card from backend response
function renderResult(r) {
  const el = document.getElementById("result");
  el.style.display = "block";
  el.style.animation = "none";
  void el.offsetWidth;
  el.style.animation = "fadeUp 0.4s ease both";

  // Verdict badge
  const badge = document.getElementById("verdict-badge");
  badge.className = "verdict-badge " + r.action;

  const icons = { deliver: "✅", quarantine: "⚠️", reject: "❌", none: "👀" };
  document.getElementById("verdict-icon").textContent = icons[r.action] || "ℹ️";
  document.getElementById("verdict-text").textContent = r.action.toUpperCase();

  // Status chip
  const statusEl = document.getElementById("res-status");
  statusEl.textContent = r.status.toUpperCase();
  statusEl.className = "chip-value " + (r.status === "pass" ? "pass" : r.status === "error" ? "warn" : "fail");

  // Action chip
  const actionEl = document.getElementById("res-action");
  actionEl.textContent = r.action.toUpperCase();
  actionEl.className = "chip-value " + (r.action === "deliver" ? "pass" : r.action === "quarantine" ? "warn" : "fail");

  // Policy chip
  document.getElementById("res-policy").textContent = (r.policy || "N/A").toUpperCase();

  // Risk score chip (if available)
  const riskEl = document.getElementById("res-risk");
  if (riskEl && r.riskScore !== undefined) {
    riskEl.textContent = r.riskScore;
    riskEl.className = "chip-value " + (r.riskScore <= 20 ? "pass" : r.riskScore <= 50 ? "warn" : "fail");
  }

  // Reason — comes from dmarc.js on the backend
  document.getElementById("res-reason").textContent = r.reason;

  // Alignment dots — comes from dmarc.js evaluateDMARC()
  document.getElementById("spf-dot").className  = "align-dot " + (r.spfAligned  ? "pass" : "fail");
  document.getElementById("dkim-dot").className = "align-dot " + (r.dkimAligned ? "pass" : "fail");
  document.getElementById("spf-align-text").textContent  = "SPF: "  + (r.spfAligned  ? "Aligned ✓" : "Not Aligned ✗");
  document.getElementById("dkim-align-text").textContent = "DKIM: " + (r.dkimAligned ? "Aligned ✓" : "Not Aligned ✗");

  // Explanation — comes from scenarioService.js on the backend
  document.getElementById("explain-box").textContent = r.explanation || "";
}


// ===================== REPORTS DASHBOARD =====================

// Load and display report summary
async function loadReportSummary() {
  try {
    const response = await fetch("/api/dmarc/reports/summary");
    if (!response.ok) throw new Error("Failed to fetch reports");

    const summary = await response.json();
    renderReportSummary(summary);
  } catch (err) {
    document.getElementById("report-summary").innerHTML = `<div class="error-box">Error loading reports: ${err.message}</div>`;
  }
}

function renderReportSummary(s) {
  const el = document.getElementById("report-summary");
  
  el.innerHTML = `
    <div class="summary-grid">
      <div class="summary-card">
        <div class="summary-label">Total Reports</div>
        <div class="summary-value">${s.total}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">DMARC Pass</div>
        <div class="summary-value pass">${s.passed}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">DMARC Fail</div>
        <div class="summary-value fail">${s.failed}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">High Risk (>70)</div>
        <div class="summary-value fail">${s.highRisk}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Avg Risk Score</div>
        <div class="summary-value">${s.averageRiskScore}</div>
      </div>
    </div>

    <div class="summary-details">
      <div class="detail-section">
        <strong>By Policy:</strong>
        <div class="policy-breakdown">
          ${Object.entries(s.byPolicy).map(([p, c]) => `<div>${p.toUpperCase()}: ${c}</div>`).join("")}
        </div>
      </div>
      <div class="detail-section">
        <strong>By Action:</strong>
        <div class="action-breakdown">
          ${Object.entries(s.byAction).map(([a, c]) => `<div>${a.toUpperCase()}: ${c}</div>`).join("")}
        </div>
      </div>
    </div>

    <div class="button-group">
      <button class="btn-secondary" onclick="loadReportsList()">View All Reports</button>
      <button class="btn-secondary" onclick="exportReportsCSV()">Export as CSV</button>
      <button class="btn-secondary" onclick="clearReports()">Clear Reports</button>
    </div>
  `;
}

// Load detailed reports list
async function loadReportsList() {
  try {
    const response = await fetch("/api/dmarc/reports?riskScoreMin=0");
    if (!response.ok) throw new Error("Failed to fetch reports");

    const data = await response.json();
    renderReportsList(data.reports);
  } catch (err) {
    document.getElementById("report-summary").innerHTML = `<div class="error-box">Error loading reports: ${err.message}</div>`;
  }
}

function renderReportsList(reports) {
  const el = document.getElementById("report-summary");
  
  if (reports.length === 0) {
    el.innerHTML = `<div class="info-box">No reports recorded yet. Run some scenarios with logging enabled.</div>`;
    return;
  }

  const rows = reports.map(r => `
    <tr>
      <td>${r.timestamp.substring(0, 19)}</td>
      <td>${r.scenario}</td>
      <td><span class="chip-value ${r.status === 'pass' ? 'pass' : 'fail'}">${r.status}</span></td>
      <td><span class="chip-value ${r.action === 'deliver' ? 'pass' : r.action === 'quarantine' ? 'warn' : 'fail'}">${r.action}</span></td>
      <td>${r.riskScore}</td>
      <td>${r.fromDomain}</td>
    </tr>
  `).join("");

  el.innerHTML = `
    <div class="table-container">
      <table class="reports-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Scenario</th>
            <th>Status</th>
            <th>Action</th>
            <th>Risk</th>
            <th>Domain</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
    <button class="btn-secondary" onclick="loadReportSummary()">Back to Summary</button>
  `;
}

// Export reports as CSV
async function exportReportsCSV() {
  try {
    const response = await fetch("/api/dmarc/reports/export/csv");
    if (!response.ok) throw new Error("Failed to export");

    const csv = await response.text();
    const blob = new Blob([csv], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "dmarc-reports.csv";
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert("Export failed: " + err.message);
  }
}

// Clear all reports
async function clearReports() {
  if (!confirm("Clear all reports? This cannot be undone.")) return;

  try {
    const response = await fetch("/api/dmarc/reports", { method: "DELETE" });
    if (!response.ok) throw new Error("Failed to clear reports");

    alert("Reports cleared");
    loadReportSummary();
  } catch (err) {
    alert("Failed to clear reports: " + err.message);
  }
}

// ===================== BEFORE/AFTER COMPARISON =====================

// Comparison attack definitions — same spoof, different policies applied
const comparisonScenarios = {
  "basic-spoof": {
    name: "Basic Spoofed Sender",
    attack: "Attacker sets From: legitbank.com but sends from evil.com. SPF and DKIM both fail alignment.",
    spf:        { status: "fail", domain: "evil.com" },
    dkim:       { status: "fail", domain: "evil.com" },
    fromDomain: "legitbank.com",
    takeaway:   "With no DMARC or p=none, this spoofed email lands in the inbox — the attack succeeds. Only p=quarantine or p=reject stops it. This is why organisations must not leave DMARC at p=none."
  },
  "ceo-fraud": {
    name: "CEO Fraud",
    attack: "Attacker registers ceo-company.com, passes SPF on that domain, but sets From: to ceo@company.com. DKIM is missing.",
    spf:        { status: "pass", domain: "ceo-company.com" },
    dkim:       { status: "fail", domain: "" },
    fromDomain: "company.com",
    takeaway:   "SPF passes on a lookalike domain but fails DMARC alignment. Without DMARC enforcement, this email reaches the inbox. With p=quarantine it goes to spam — the finance team may still see it. Only p=reject fully blocks the attack."
  },
  "banking-phish": {
    name: "Banking Phishing",
    attack: "Attacker fully spoofs dbs.com.sg — forges the From: header. No valid SPF or DKIM for the real domain.",
    spf:        { status: "fail", domain: "phish-server.com" },
    dkim:       { status: "fail", domain: "phish-server.com" },
    fromDomain: "dbs.com.sg",
    takeaway:   "A mass phishing campaign against a bank. Without p=reject, thousands of spoofed emails reach customer inboxes. Many major banks now enforce p=reject specifically to prevent this. The difference between none and reject is the difference between a successful attack and a blocked one."
  },
  "spf-misalign": {
    name: "SPF Pass, Misaligned",
    attack: "Attacker has a valid SPF record for evil.com. SPF passes — but the From: shows legitbank.com. This bypasses SPF-only checks.",
    spf:        { status: "pass", domain: "evil.com" },
    dkim:       { status: "fail", domain: "" },
    fromDomain: "legitbank.com",
    takeaway:   "This is the most important scenario — SPF passes but DMARC alignment fails. Without DMARC, this attack succeeds even though SPF is configured. This is exactly the gap DMARC was designed to close. Only with DMARC enforcement does this get caught."
  }
};

// Run all four policy columns for the selected attack
async function loadComparison(key) {
  const s = comparisonScenarios[key];
  if (!s) return;

  // Highlight selected button
  document.querySelectorAll('#tab-comparison .scenario-btn').forEach(b => {
    b.style.borderColor = '';
    b.style.color = '';
  });
  event.currentTarget.style.borderColor = 'var(--accent)';
  event.currentTarget.style.color = 'var(--accent)';

  // Show attack description
  document.getElementById("comparison-attack-box").style.display = "block";
  document.getElementById("comparison-attack-text").textContent = s.attack;

  // Show loading state
  const resultEl = document.getElementById("comparison-result");
  resultEl.style.display = "block";
  ['nodmarc','none','quarantine','reject'].forEach(id => {
    document.getElementById(`comp-col-${id}`).innerHTML = `<div style="color:var(--muted); font-family:var(--mono); font-size:12px; text-align:center; padding:20px;">Loading...</div>`;
  });

  // Fire all four evaluations in parallel
  try {
    const evaluate = (policy) => fetch("/api/dmarc/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        spf: s.spf,
        dkim: s.dkim,
        parsed: { policy, fromDomain: s.fromDomain, pct: 100, aspf: "r", adkim: "r" },
        log: true
      })
    }).then(r => r.json());

    // "No DMARC" = simulate by forcing deliver regardless (p=none + no alignment penalty)
    const [rNone, rQuarantine, rReject] = await Promise.all([
      evaluate("none"),
      evaluate("quarantine"),
      evaluate("reject")
    ]);

    // No DMARC column — always delivers, no checking at all
    const rNoDMARC = {
      status: "fail",
      action: "deliver",
      reason: "No DMARC record — mail server has no policy to enforce",
      riskScore: 95,
      spfAligned: false,
      dkimAligned: false
    };

    renderComparisonColumn("nodmarc", rNoDMARC, "No DMARC record published. The mail server has nothing to enforce — spoofed emails are delivered with no checks.");
    renderComparisonColumn("none",       rNone,       "DMARC exists but p=none means no action is taken. The spoof is detected but the email still delivers. Useful for monitoring but not protection.");
    renderComparisonColumn("quarantine", rQuarantine, "DMARC detects the spoof and sends the email to the spam/junk folder. Better protection — but the user may still see and open it.");
    renderComparisonColumn("reject",     rReject,     "DMARC detects the spoof and the mail server rejects the email entirely. It never reaches the inbox. Maximum protection.");

    document.getElementById("comparison-takeaway").textContent = s.takeaway;

    // Animate in
    resultEl.style.animation = "none";
    void resultEl.offsetWidth;
    resultEl.style.animation = "fadeUp 0.4s ease both";

  } catch (err) {
    ['nodmarc','none','quarantine','reject'].forEach(id => {
      document.getElementById(`comp-col-${id}`).innerHTML = `<div class="error-box">Server error. Make sure node app.js is running.</div>`;
    });
  }
}

function renderComparisonColumn(colId, r, description) {
  const icons      = { deliver: "✉️", quarantine: "📁", reject: "🚫" };
  const riskColor  = r.riskScore <= 20 ? "pass" : r.riskScore <= 50 ? "warn" : "fail";

  document.getElementById(`comp-col-${colId}`).innerHTML = `
    <div class="comp-verdict ${r.action}">
      <span>${icons[r.action] || "ℹ️"}</span>
      <span>${r.action.toUpperCase()}</span>
    </div>

    <div class="comp-risk">
      <span class="comp-risk-value ${riskColor}">${r.riskScore}</span>
      RISK SCORE
    </div>

    <div class="comp-outcome">${r.reason}</div>

    <div class="comp-detail">${description}</div>
  `;
}
