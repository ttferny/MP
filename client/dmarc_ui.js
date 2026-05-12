// =============================================================
// dmarc_ui.js — DMARC Policy Engine Frontend Logic
// Author:  Zircon Lee
// Scope:   All frontend JavaScript for the DMARC simulator page
//
// Sections:
//   1. Scenario metadata  — display data for the 13 scenarios
//   2. Scenarios tab      — loadScenario(), runDMARC(), renderResult()
//   3. Reports tab        — loadReportSummary(), renderReportSummary(),
//                           loadReportsList(), renderReportsList(),
//                           exportReportsCSV(), clearReports()
//   4. Before/After tab   — comparisonScenarios, loadComparison(),
//                           renderComparisonColumn()
//   5. DMARC Audit tab    — sampleRecords, loadSampleRecord(),
//                           runAudit(), renderAuditResult()
//
// All fetch calls go to /api/dmarc/* (server/routes/dmarcRoutes.js)
// =============================================================


// =============================================================
// SECTION 1 — SCENARIO METADATA
// Frontend display data for each of the 13 scenarios.
// The actual SPF/DKIM values and policy logic live in
// scenarioService.js on the backend — this is only for
// populating the Step 2 detail panel in the UI.
// =============================================================

const scenarioMeta = {

  // Legitimate email — baseline, all checks pass, delivered normally
  "legitimate": {
    icon: "✅", name: "Legitimate Email",
    fromDomain: "legitbank.com", defaultPolicy: "reject",
    desc:   "A real email from legitbank.com, sent from their authorised server with a valid DKIM signature.",
    attack: "No attack. This is the baseline — a genuine email that should always be delivered."
  },

  // Basic spoof — attacker forges From: header, SPF and DKIM both fail
  "basic-spoof": {
    icon: "❌", name: "Basic Spoofed Sender",
    fromDomain: "legitbank.com", defaultPolicy: "reject",
    desc:   "An attacker sends an email pretending to be legitbank.com but from their own server with no valid signature.",
    attack: "Attacker sets From: legitbank.com but sends from evil.com. SPF and DKIM both fail alignment."
  },

  // CEO fraud — SPF passes on lookalike domain, DKIM missing, p=quarantine
  "ceo-fraud": {
    icon: "🎭", name: "CEO Fraud",
    fromDomain: "company.com", defaultPolicy: "quarantine",
    desc:   "Attacker impersonates a company CEO to trick the finance team into transferring money.",
    attack: "Attacker registers ceo-company.com (looks similar), passes SPF on that domain, but the From: shows ceo@company.com. DKIM is missing."
  },

  // Banking phishing — full domain spoof, SPF and DKIM both fail
  "banking-phish": {
    icon: "🏦", name: "Banking Phishing",
    fromDomain: "dbs.com.sg", defaultPolicy: "reject",
    desc:   "Mass phishing campaign spoofing a bank to steal customer credentials via a fake login page.",
    attack: "Attacker fully spoofs dbs.com.sg — forges the From: header. No valid SPF or DKIM for the real domain."
  },

  // Weak policy — p=none, attack is detected but email still delivered
  "monitor-only": {
    icon: "👀", name: "Weak DMARC Policy",
    fromDomain: "example.com", defaultPolicy: "none",
    desc:   "The domain has DMARC set up but only in monitoring mode — a common misconfiguration.",
    attack: "Same spoofed email as basic-spoof, but the domain owner set p=none meaning DMARC takes no action."
  },

  // SPF misalign — SPF passes but for the wrong domain (the key DMARC use case)
  "spf-misalign": {
    icon: "🔀", name: "SPF Pass, Misaligned",
    fromDomain: "legitbank.com", defaultPolicy: "reject",
    desc:   "A subtle attack where SPF passes but on the wrong domain — exactly the gap DMARC was designed to close.",
    attack: "Attacker's server has a valid SPF record for evil.com. SPF passes. But the From: header shows legitbank.com. Without DMARC, this slips through."
  },

  // Strict alignment fail — subdomain fails aspf=s / adkim=s
  "strict-fail": {
    icon: "🔒", name: "Strict Alignment Fail",
    fromDomain: "legitbank.com", defaultPolicy: "reject",
    desc:   "Email sent from a subdomain mail.legitbank.com but DMARC is set to strict alignment.",
    attack: "Not an attack — this shows how strict mode can break legitimate subdomain senders."
  },

  // Relaxed alignment pass — same subdomain passes aspf=r / adkim=r
  "relaxed-pass": {
    icon: "🔓", name: "Relaxed Alignment Pass",
    fromDomain: "legitbank.com", defaultPolicy: "reject",
    desc:   "Same subdomain email but DMARC is set to relaxed alignment — the default.",
    attack: "Not an attack — shows how relaxed mode correctly allows legitimate subdomain senders."
  },

  // Forwarded email — SPF breaks when forwarded through Gmail
  "forwarded-email": {
    icon: "📧", name: "Forwarded Email",
    fromDomain: "example.com", defaultPolicy: "reject",
    desc:   "A legitimate email forwarded by a third-party service like Gmail, which changes the sending server.",
    attack: "Not an attack — shows a common legitimate scenario that DMARC can break."
  },

  // Subdomain spoof — attacker registers lookalike subdomain, passes relaxed SPF
  "subdomain-spoof": {
    icon: "🚨", name: "Subdomain Spoof Attack",
    fromDomain: "company.com", defaultPolicy: "reject",
    desc:   "Attacker creates a lookalike subdomain to bypass organisational domain checks.",
    attack: "Attacker registers newsletter.company.com and gets SPF to pass. From: is set to alerts@company.com."
  },

  // Partial enforcement pass — pct=50, legitimate email passes regardless
  "pct-50-pass": {
    icon: "50️⃣", name: "Partial Enforcement (Pass)",
    fromDomain: "legitbank.com", defaultPolicy: "quarantine",
    desc:   "A legitimate email with p=quarantine pct=50. Only 50% of emails get the policy action.",
    attack: "Not an attack — shows a gradual rollout strategy, but creates security gaps."
  },

  // Partial enforcement fail — pct=50, half of spoofed emails slip through
  "pct-50-fail": {
    icon: "⚠️", name: "Partial Enforcement (Fail)",
    fromDomain: "company.com", defaultPolicy: "quarantine",
    desc:   "Spoofed email with p=quarantine pct=50. Only 50% get quarantined, 50% slip through.",
    attack: "Attacker sends spoofed email. With pct=50, roughly half bypass quarantine and reach inboxes."
  },

  // Subdomain policy — sp= tag gives subdomains a different policy to main domain
  "subdomain-policy": {
    icon: "🔗", name: "Subdomain Policy (sp=)",
    fromDomain: "mail.legitbank.com", defaultPolicy: "reject",
    desc:   "Email from subdomain with sp=none (subdomain policy), main domain has p=reject.",
    attack: "Not an attack — shows how sp= allows subdomains to have different policies."
  },
};

// Tracks which scenario is currently selected — used by runDMARC()
let currentScenario = null;


// =============================================================
// SECTION 2 — SCENARIOS TAB
// =============================================================

// loadScenario — called when a scenario card is clicked in Step 1
// Populates the Step 2 detail panel with the scenario's metadata
// and shows it. The backend call happens when the user clicks Run.
function loadScenario(key) {
  const s = scenarioMeta[key];
  if (!s) return;
  currentScenario = key;

  // Highlight the clicked card, remove highlight from others
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
  event.currentTarget.classList.add('active');

  // Populate Step 2 detail panel fields
  document.getElementById("detail-icon").textContent   = s.icon;
  document.getElementById("detail-name").textContent   = s.name;
  document.getElementById("detail-desc").textContent   = s.desc;
  document.getElementById("detail-attack").textContent = s.attack;
  document.getElementById("dmarc-policy").value        = s.defaultPolicy;
  document.getElementById("from-domain").value         = s.fromDomain;

  // Show Step 2, hide Step 3 (previous result)
  const detailCard = document.getElementById("scenario-detail");
  detailCard.style.display = "block";
  detailCard.style.animation = "none";
  void detailCard.offsetWidth;  // force reflow to restart animation
  detailCard.style.animation = "fadeUp 0.4s ease both";
  document.getElementById("result").style.display = "none";
}

// runDMARC — called when "Run DMARC Policy Engine" button is clicked
// Reads the user's policy/alignment overrides and sends the scenario
// to POST /api/dmarc/scenarios/:key on the backend.
// The backend runs evaluateDMARC() in dmarc.js and returns the result.
async function runDMARC() {
  if (!currentScenario) return;

  // Read user-adjustable settings from Step 2 form
  const policy = document.getElementById("dmarc-policy").value;
  const aspf   = document.getElementById("aspf-mode").value;
  const adkim  = document.getElementById("adkim-mode").value;
  const spEl   = document.getElementById("sp-mode");
  const sp     = spEl ? spEl.value || null : null;

  try {
    const response = await fetch(`/api/dmarc/scenarios/${currentScenario}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // log:true records this evaluation in aggregateReporter.js
      body: JSON.stringify({ policy, aspf, adkim, sp, log: true })
    });

    if (!response.ok) throw new Error("Server error: " + response.status);

    const result = await response.json();
    renderResult(result);

  } catch (err) {
    // Show a server-unreachable error in the result card
    renderResult({
      status: "error", action: "none",
      reason: "Could not reach server. Make sure node app.js is running.",
      policy: "N/A", spfAligned: false, dkimAligned: false, explanation: ""
    });
  }
}

// renderResult — populates and shows the Step 3 result card
// Called with the JSON response from POST /api/dmarc/scenarios/:key
// Data originates from evaluateDMARC() in dmarc.js
function renderResult(r) {
  const el = document.getElementById("result");
  el.style.display = "block";
  el.style.animation = "none";
  void el.offsetWidth;
  el.style.animation = "fadeUp 0.4s ease both";

  // Verdict badge — class controls colour (deliver=green, quarantine=amber, reject=red)
  const badge = document.getElementById("verdict-badge");
  badge.className = "verdict-badge " + r.action;
  const icons = { deliver: "✅", quarantine: "⚠️", reject: "❌", none: "👀" };
  document.getElementById("verdict-icon").textContent = icons[r.action] || "ℹ️";
  document.getElementById("verdict-text").textContent = r.action.toUpperCase();

  // Status chip — pass (green) / fail (red) / error (amber)
  const statusEl = document.getElementById("res-status");
  statusEl.textContent = r.status.toUpperCase();
  statusEl.className = "chip-value " + (r.status === "pass" ? "pass" : r.status === "error" ? "warn" : "fail");

  // Action chip — deliver (green) / quarantine (amber) / reject (red)
  const actionEl = document.getElementById("res-action");
  actionEl.textContent = r.action.toUpperCase();
  actionEl.className = "chip-value " + (r.action === "deliver" ? "pass" : r.action === "quarantine" ? "warn" : "fail");

  // Policy chip — which p= value was applied
  document.getElementById("res-policy").textContent = (r.policy || "N/A").toUpperCase();

  // Risk score chip — 0-100, calculated by calculateRiskScore() in dmarc.js
  // Green ≤20, Amber ≤50, Red >50
  const riskEl = document.getElementById("res-risk");
  if (riskEl && r.riskScore !== undefined) {
    riskEl.textContent = r.riskScore;
    riskEl.className = "chip-value " + (r.riskScore <= 20 ? "pass" : r.riskScore <= 50 ? "warn" : "fail");
  }

  // Reason text — one-line explanation from evaluateDMARC() in dmarc.js
  document.getElementById("res-reason").textContent = r.reason;

  // SPF alignment dot — green if SPF domain matched From: domain, red if not
  document.getElementById("spf-dot").className  = "align-dot " + (r.spfAligned  ? "pass" : "fail");
  document.getElementById("spf-align-text").textContent = "SPF: " + (r.spfAligned ? "Aligned ✓" : "Not Aligned ✗");

  // DKIM alignment dot — green if DKIM domain matched From: domain, red if not
  document.getElementById("dkim-dot").className = "align-dot " + (r.dkimAligned ? "pass" : "fail");
  document.getElementById("dkim-align-text").textContent = "DKIM: " + (r.dkimAligned ? "Aligned ✓" : "Not Aligned ✗");

  // Plain-English explanation from scenarioService.js on the backend
  document.getElementById("explain-box").textContent = r.explanation || "";
}


// =============================================================
// SECTION 3 — REPORTS TAB
// Loads and displays evaluation history from aggregateReporter.js
// =============================================================

// loadReportSummary — fetches aggregate stats from GET /api/dmarc/reports/summary
// Auto-called when the Reports tab is opened via switchTab()
async function loadReportSummary() {
  try {
    const response = await fetch("/api/dmarc/reports/summary");
    if (!response.ok) throw new Error("Failed to fetch reports");
    const summary = await response.json();
    renderReportSummary(summary);
  } catch (err) {
    document.getElementById("report-summary").innerHTML =
      `<div class="error-box">Error loading reports: ${err.message}</div>`;
  }
}

// renderReportSummary — renders stat cards and breakdown tables
// Called with the response from GET /api/dmarc/reports/summary
function renderReportSummary(s) {
  document.getElementById("report-summary").innerHTML = `
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
          ${Object.entries(s.byPolicy).map(([p, c]) => `<div>${p.toUpperCase()}: ${c}</div>`).join("") || "<div>No data yet</div>"}
        </div>
      </div>
      <div class="detail-section">
        <strong>By Action:</strong>
        <div class="action-breakdown">
          ${Object.entries(s.byAction).map(([a, c]) => `<div>${a.toUpperCase()}: ${c}</div>`).join("") || "<div>No data yet</div>"}
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

// loadReportsList — fetches all individual report entries
// from GET /api/dmarc/reports and renders them as a table
async function loadReportsList() {
  try {
    const response = await fetch("/api/dmarc/reports?riskScoreMin=0");
    if (!response.ok) throw new Error("Failed to fetch reports");
    const data = await response.json();
    renderReportsList(data.reports);
  } catch (err) {
    document.getElementById("report-summary").innerHTML =
      `<div class="error-box">Error loading reports: ${err.message}</div>`;
  }
}

// renderReportsList — builds the HTML table of individual report rows
// Each row = one evaluation logged with log:true
function renderReportsList(reports) {
  const el = document.getElementById("report-summary");

  if (reports.length === 0) {
    el.innerHTML = `<div class="info-box">No reports recorded yet. Run some scenarios with logging enabled.</div>`;
    return;
  }

  // Build table rows — colour-code status, action by outcome
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
            <th>Time</th><th>Scenario</th><th>Status</th>
            <th>Action</th><th>Risk</th><th>Domain</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <button class="btn-secondary" onclick="loadReportSummary()">Back to Summary</button>
  `;
}

// exportReportsCSV — downloads all reports as a CSV file
// Calls GET /api/dmarc/reports/export/csv → exportReportsAsCSV() in aggregateReporter.js
async function exportReportsCSV() {
  try {
    const response = await fetch("/api/dmarc/reports/export/csv");
    if (!response.ok) throw new Error("Failed to export");
    const csv  = await response.text();
    // Create a temporary link element to trigger the browser download
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = window.URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "dmarc-reports.csv"; a.click();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert("Export failed: " + err.message);
  }
}

// clearReports — deletes all stored reports via DELETE /api/dmarc/reports
// Calls clearReports() in aggregateReporter.js on the backend
async function clearReports() {
  if (!confirm("Clear all reports? This cannot be undone.")) return;
  try {
    const response = await fetch("/api/dmarc/reports", { method: "DELETE" });
    if (!response.ok) throw new Error("Failed to clear reports");
    alert("Reports cleared");
    loadReportSummary(); // reload the now-empty summary
  } catch (err) {
    alert("Failed to clear reports: " + err.message);
  }
}


// =============================================================
// SECTION 4 — BEFORE/AFTER COMPARISON TAB
// Runs the same spoofed email through four DMARC configurations
// simultaneously via POST /api/dmarc/evaluate
// =============================================================

// comparisonScenarios — hardcoded SPF/DKIM values for each attack type
// The user picks an attack, then all four policy columns are evaluated
// against these same inputs to show how policy strength changes the outcome
const comparisonScenarios = {

  // Basic spoof — both SPF and DKIM fail, simplest attack
  "basic-spoof": {
    name: "Basic Spoofed Sender",
    attack: "Attacker sets From: legitbank.com but sends from evil.com. SPF and DKIM both fail alignment.",
    spf:        { status: "fail", domain: "evil.com" },
    dkim:       { status: "fail", domain: "evil.com" },
    fromDomain: "legitbank.com",
    takeaway:   "With no DMARC or p=none, this spoofed email lands in the inbox — the attack succeeds. Only p=quarantine or p=reject stops it. This is why organisations must not leave DMARC at p=none."
  },

  // CEO fraud — SPF passes on lookalike domain, DKIM missing
  "ceo-fraud": {
    name: "CEO Fraud",
    attack: "Attacker registers ceo-company.com, passes SPF on that domain, but sets From: to ceo@company.com. DKIM is missing.",
    spf:        { status: "pass", domain: "ceo-company.com" },
    dkim:       { status: "fail", domain: "" },
    fromDomain: "company.com",
    takeaway:   "SPF passes on a lookalike domain but fails DMARC alignment. Without DMARC enforcement, this email reaches the inbox. With p=quarantine it goes to spam — the finance team may still see it. Only p=reject fully blocks the attack."
  },

  // Banking phishing — full domain spoof of a real bank
  "banking-phish": {
    name: "Banking Phishing",
    attack: "Attacker fully spoofs dbs.com.sg — forges the From: header. No valid SPF or DKIM for the real domain.",
    spf:        { status: "fail", domain: "phish-server.com" },
    dkim:       { status: "fail", domain: "phish-server.com" },
    fromDomain: "dbs.com.sg",
    takeaway:   "A mass phishing campaign against a bank. Without p=reject, thousands of spoofed emails reach customer inboxes. Many major banks now enforce p=reject specifically to prevent this. The difference between none and reject is the difference between a successful attack and a blocked one."
  },

  // SPF misalign — the most important DMARC scenario
  // Shows that SPF passing is not enough without alignment checking
  "spf-misalign": {
    name: "SPF Pass, Misaligned",
    attack: "Attacker has a valid SPF record for evil.com. SPF passes — but the From: shows legitbank.com. This bypasses SPF-only checks.",
    spf:        { status: "pass", domain: "evil.com" },
    dkim:       { status: "fail", domain: "" },
    fromDomain: "legitbank.com",
    takeaway:   "This is the most important scenario — SPF passes but DMARC alignment fails. Without DMARC, this attack succeeds even though SPF is configured. This is exactly the gap DMARC was designed to close. Only with DMARC enforcement does this get caught."
  }
};

// loadComparison — called when an attack button is clicked in the Before/After tab
// Fires four parallel POST /api/dmarc/evaluate calls (one per policy)
// and renders all four results side by side
async function loadComparison(key) {
  const s = comparisonScenarios[key];
  if (!s) return;

  // Highlight selected attack button
  document.querySelectorAll('#tab-comparison .scenario-btn').forEach(b => {
    b.style.borderColor = ''; b.style.color = '';
  });
  event.currentTarget.style.borderColor = 'var(--accent)';
  event.currentTarget.style.color       = 'var(--accent)';

  // Show the attack description box
  document.getElementById("comparison-attack-box").style.display = "block";
  document.getElementById("comparison-attack-text").textContent  = s.attack;

  // Show loading placeholders in each column while fetching
  const resultEl = document.getElementById("comparison-result");
  resultEl.style.display = "block";
  ['nodmarc','none','quarantine','reject'].forEach(id => {
    document.getElementById(`comp-col-${id}`).innerHTML =
      `<div style="color:var(--muted); font-family:var(--mono); font-size:12px; text-align:center; padding:20px;">Loading...</div>`;
  });

  try {
    // Helper: fires one POST /api/dmarc/evaluate with a given policy
    const evaluate = (policy) => fetch("/api/dmarc/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        spf:    s.spf,
        dkim:   s.dkim,
        parsed: { policy, fromDomain: s.fromDomain, pct: 100, aspf: "r", adkim: "r" },
        log:    true  // record in aggregate reporter
      })
    }).then(r => r.json());

    // Fire all three real policy evaluations in parallel
    const [rNone, rQuarantine, rReject] = await Promise.all([
      evaluate("none"),
      evaluate("quarantine"),
      evaluate("reject")
    ]);

    // "No DMARC" is simulated — no backend call needed, always delivers
    const rNoDMARC = {
      status: "fail", action: "deliver",
      reason: "No DMARC record — mail server has no policy to enforce",
      riskScore: 95, spfAligned: false, dkimAligned: false
    };

    // Render each of the four columns
    renderComparisonColumn("nodmarc",    rNoDMARC,    "No DMARC record published. The mail server has nothing to enforce — spoofed emails are delivered with no checks.");
    renderComparisonColumn("none",       rNone,       "DMARC exists but p=none means no action is taken. The spoof is detected but the email still delivers. Useful for monitoring but not protection.");
    renderComparisonColumn("quarantine", rQuarantine, "DMARC detects the spoof and sends the email to the spam/junk folder. Better protection — but the user may still see and open it.");
    renderComparisonColumn("reject",     rReject,     "DMARC detects the spoof and the mail server rejects the email entirely. It never reaches the inbox. Maximum protection.");

    // Show the takeaway explanation
    document.getElementById("comparison-takeaway").textContent = s.takeaway;

    // Animate the result grid in
    resultEl.style.animation = "none";
    void resultEl.offsetWidth;
    resultEl.style.animation = "fadeUp 0.4s ease both";

  } catch (err) {
    ['nodmarc','none','quarantine','reject'].forEach(id => {
      document.getElementById(`comp-col-${id}`).innerHTML =
        `<div class="error-box">Server error. Make sure node app.js is running.</div>`;
    });
  }
}

// renderComparisonColumn — populates one of the four policy columns
// colId      — "nodmarc", "none", "quarantine", or "reject"
// r          — result object from evaluateDMARC()
// description — plain-English explanation of this column's behaviour
function renderComparisonColumn(colId, r, description) {
  const icons     = { deliver: "✉️", quarantine: "📁", reject: "🚫" };
  const riskColor = r.riskScore <= 20 ? "pass" : r.riskScore <= 50 ? "warn" : "fail";

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


// =============================================================
// SECTION 5 — DMARC AUDIT TAB
// Sends a raw DMARC TXT record string to POST /api/dmarc/audit
// The backend runs dmarcAuditor.js and returns a grade, score,
// issues list, and recommendations.
// =============================================================

// sampleRecords — preset records for the Quick Load buttons
// Lets the user demo the auditor without typing a real DMARC record
const sampleRecords = {
  strong:   { domain: "example.com",  record: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; aspf=r; adkim=r" },
  moderate: { domain: "moderate.com", record: "v=DMARC1; p=quarantine; pct=50; aspf=r; adkim=r" },
  weak:     { domain: "weak.com",     record: "v=DMARC1; p=none" },
  none:     { domain: "nodmarc.com",  record: "" }  // blank = no record
};

// loadSampleRecord — fills the audit form with a preset record
// Called by the Quick Load buttons in the Audit tab
function loadSampleRecord(key) {
  const s = sampleRecords[key];
  if (!s) return;

  document.getElementById("audit-domain").value  = s.domain;
  document.getElementById("audit-record").value  = s.record;

  // Highlight selected button, reset others
  document.querySelectorAll('#tab-audit .scenario-btn').forEach(b => {
    b.style.borderColor = ''; b.style.color = '';
  });
  event.currentTarget.style.borderColor = 'var(--accent)';
  event.currentTarget.style.color       = 'var(--accent)';

  // Hide any previous result
  document.getElementById("audit-result").style.display = "none";
}

// runAudit — called when "Audit DMARC Record" button is clicked
// Sends domain + raw record to POST /api/dmarc/audit
// Backend runs auditDMARC() in dmarcAuditor.js and returns the grade
async function runAudit() {
  const domain      = document.getElementById("audit-domain").value.trim();
  const dmarcRecord = document.getElementById("audit-record").value.trim() || null;

  if (!domain) {
    alert("Please enter a domain name.");
    return;
  }

  try {
    const response = await fetch("/api/dmarc/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // dmarcRecord is null if the textarea is empty (simulates no record)
      body: JSON.stringify({ domain, dmarcRecord })
    });

    if (!response.ok) throw new Error("Server error: " + response.status);

    const result = await response.json();
    renderAuditResult(result);

  } catch (err) {
    const el = document.getElementById("audit-result");
    el.style.display = "block";
    el.innerHTML = `<div class="error-box">Could not reach server: ${err.message}. Make sure node app.js is running.</div>`;
  }
}

// renderAuditResult — populates and shows the audit result card
// Called with the JSON response from POST /api/dmarc/audit
// Data originates from auditDMARC() in dmarcAuditor.js
function renderAuditResult(r) {
  const el = document.getElementById("audit-result");
  el.style.display = "block";
  el.style.animation = "none";
  void el.offsetWidth;
  el.style.animation = "fadeUp 0.4s ease both";

  // Grade badge — letter A/B/C/D/F, coloured by grade-X CSS class
  const badge = document.getElementById("audit-grade-badge");
  badge.textContent = r.grade;
  badge.className   = `grade-${r.grade}`;
  // Reset inline styles so CSS class can control appearance
  badge.style.cssText = "width:80px; height:80px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-family:var(--mono); font-size:40px; font-weight:700; flex-shrink:0;";

  // Grade description — from gradeDescriptions object in dmarcAuditor.js
  document.getElementById("audit-grade-desc").textContent = r.gradeDescription || "";

  // Score bar — width as percentage of 100, colour by severity
  const scoreBar   = document.getElementById("audit-score-bar");
  const scoreColor = r.score >= 90 ? "var(--pass)" : r.score >= 60 ? "var(--warn)" : "var(--fail)";
  scoreBar.style.width      = r.score + "%";
  scoreBar.style.background = scoreColor;
  document.getElementById("audit-score-val").textContent = r.score;
  document.getElementById("audit-score-val").style.color = scoreColor;

  // DMARC tag breakdown — one chip per tag (p=, pct=, sp=, rua=, aspf=, adkim=)
  // Each tag is colour-coded: good=green, warn=amber, bad=red, muted=grey
  const tagsEl = document.getElementById("audit-tags");
  if (r.dmarc) {
    const d = r.dmarc;
    const policyColor = d.policy === 'reject' ? 'good' : d.policy === 'quarantine' ? 'warn' : 'bad';
    const pctColor    = d.pct === 100 ? 'good' : d.pct >= 50 ? 'warn' : 'bad';
    const ruaColor    = d.rua ? 'good' : 'bad';
    const spColor     = d.sp === 'reject' ? 'good' : d.sp === 'quarantine' ? 'warn' : d.sp === 'none' ? 'bad' : 'muted';

    tagsEl.innerHTML = `
      <div class="audit-tag-grid">
        <div class="audit-tag">
          <div class="audit-tag-key">p= (policy)</div>
          <div class="audit-tag-value ${policyColor}">${d.policy || "missing"}</div>
        </div>
        <div class="audit-tag">
          <div class="audit-tag-key">pct= (enforcement)</div>
          <div class="audit-tag-value ${pctColor}">${d.pct}%</div>
        </div>
        <div class="audit-tag">
          <div class="audit-tag-key">sp= (subdomains)</div>
          <div class="audit-tag-value ${spColor}">${d.sp || "not set"}</div>
        </div>
        <div class="audit-tag">
          <div class="audit-tag-key">rua= (reports)</div>
          <div class="audit-tag-value ${ruaColor}">${d.rua ? "configured" : "not set"}</div>
        </div>
        <div class="audit-tag">
          <div class="audit-tag-key">aspf= (SPF align)</div>
          <div class="audit-tag-value">${d.aspf === 'r' ? 'relaxed' : 'strict'}</div>
        </div>
        <div class="audit-tag">
          <div class="audit-tag-key">adkim= (DKIM align)</div>
          <div class="audit-tag-value">${d.adkim === 'r' ? 'relaxed' : 'strict'}</div>
        </div>
      </div>
    `;
  } else {
    // No DMARC record — show a message instead of tag chips
    tagsEl.innerHTML = `<div class="reason-box" style="color:var(--fail);">No DMARC record found for ${r.domain}.</div>`;
  }

  // Issues list — each item from r.issues array (from dmarcAuditor.js)
  const issuesSec = document.getElementById("audit-issues-section");
  const issuesEl  = document.getElementById("audit-issues");
  if (r.issues && r.issues.length > 0) {
    issuesSec.style.display = "block";
    issuesEl.innerHTML = r.issues.map(i => `<div class="audit-issue">⚠ ${i}</div>`).join("");
  } else {
    issuesSec.style.display = "none";
  }

  // Recommendations list — each item from r.recommendations array (from dmarcAuditor.js)
  const recsSec = document.getElementById("audit-recs-section");
  const recsEl  = document.getElementById("audit-recs");
  if (r.recommendations && r.recommendations.length > 0) {
    recsSec.style.display = "block";
    recsEl.innerHTML = r.recommendations.map(rec => `<div class="audit-rec">→ ${rec}</div>`).join("");
  } else {
    recsSec.style.display = "none";
  }

  // Scroll the result into view smoothly
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}