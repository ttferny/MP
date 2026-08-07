// Scenario metadata for the frontend (icons, descriptions, attack info)
// The actual SPF/DKIM values and policy logic live in scenarioService.js on the backend
// Zircon
const scenarioMeta = {
  "legitimate":         { icon: "", name: "Legitimate Email",        defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "A real email from legitbank.com, sent from their authorised server with a valid DKIM signature.",                               attack: "No attack. This is the baseline — a genuine email that should always be delivered."                                                                             },
  "basic-spoof":        { icon: "", name: "Basic Spoofed Sender",    defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "An attacker sends an email pretending to be legitbank.com but from their own server with no valid signature.",                   attack: "Attacker sets From: legitbank.com but sends from evil.com. SPF and DKIM both fail alignment."                                                                   },
  "ceo-fraud":          { icon: "", name: "CEO Fraud",               defaultPolicy: "quarantine", fromDomain: "company.com",      desc: "Attacker impersonates a company CEO to trick the finance team into transferring money.",                                         attack: "Attacker registers ceo-company.com (looks similar), passes SPF on that domain, but the From: shows ceo@company.com. DKIM is missing."                          },
  "banking-phish":      { icon: "", name: "Banking Phishing",        defaultPolicy: "reject",     fromDomain: "dbs.com.sg",       desc: "Mass phishing campaign spoofing a bank to steal customer credentials via a fake login page.",                                    attack: "Attacker fully spoofs dbs.com.sg — forges the From: header. No valid SPF or DKIM for the real domain."                                                          },
  "monitor-only":       { icon: "", name: "Weak DMARC Policy",       defaultPolicy: "none",       fromDomain: "example.com",      desc: "The domain has DMARC set up but only in monitoring mode — a common misconfiguration.",                                          attack: "Same spoofed email as basic-spoof, but the domain owner set p=none meaning DMARC takes no action."                                                              },
  "spf-misalign":       { icon: "", name: "SPF Pass, Misaligned",    defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "A subtle attack where SPF passes but on the wrong domain — exactly the gap DMARC was designed to close.",                       attack: "Attacker's server has a valid SPF record for evil.com. SPF passes. But the From: header shows legitbank.com. Without DMARC, this slips through."              },
  "strict-fail":        { icon: "", name: "Strict Alignment Fail",   defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "Email sent from a subdomain mail.legitbank.com but DMARC is set to strict alignment.",                                          attack: "Not an attack — this shows how strict mode can break legitimate subdomain senders."                                                                             },
  "relaxed-pass":       { icon: "", name: "Relaxed Alignment Pass",  defaultPolicy: "reject",     fromDomain: "legitbank.com",    desc: "Same subdomain email but DMARC is set to relaxed alignment — the default.",                                                     attack: "Not an attack — shows how relaxed mode correctly allows legitimate subdomain senders."                                                                         },
  "forwarded-email":    { icon: "", name: "Forwarded Email",         defaultPolicy: "reject",     fromDomain: "example.com",      desc: "A legitimate email forwarded by a third-party service like Gmail, which changes the From: header.",                               attack: "Not an attack — shows a common legitimate scenario that DMARC can break."                                                                                     },
  "subdomain-spoof":    { icon: "", name: "Subdomain Spoof Attack",  defaultPolicy: "reject",     fromDomain: "company.com",      desc: "Attacker creates a lookalike subdomain to bypass organizational domain checks.",                                                 attack: "Attacker registers newsletter.company.com and gets SPF to pass. From: is set to alerts@company.com."                                                           },
  "pct-50-pass":        { icon: "", name: "Partial Enforcement (Pass)", defaultPolicy: "quarantine", fromDomain: "legitbank.com",    desc: "A legitimate email with p=quarantine pct=50. Only 50% of emails get the policy action.",                                     attack: "Not an attack — shows a gradual rollout strategy, but creates security gaps."                                                                                   },
  "pct-50-fail":        { icon: "", name: "Partial Enforcement (Fail)", defaultPolicy: "quarantine", fromDomain: "company.com",      desc: "Spoofed email with p=quarantine pct=50. Only 50% get quarantined, 50% slip through.",                                     attack: "Attacker sends spoofed email. With pct=50, roughly half bypass quarantine and reach inboxes."                                                                 },
  "subdomain-policy":   { icon: "", name: "Subdomain Policy (sp=)",  defaultPolicy: "reject",     fromDomain: "mail.legitbank.com", desc: "Email from subdomain with sp=none (subdomain policy), main domain has p=reject.",                                               attack: "Not an attack — shows how sp= allows subdomains to have different policies."                                                                                   },
};

let currentScenario = null;

// Toggle the advanced SPF/DKIM strictness + subdomain policy controls
function toggleAdvancedPolicy() {
  const el = document.getElementById('advanced-policy-settings');
  const btn = document.getElementById('advanced-toggle-btn');
  const isHidden = el.style.display === 'none';
  el.style.display = isHidden ? 'block' : 'none';
  btn.textContent = isHidden
    ? 'Hide Advanced Settings'
    : 'Show Advanced Settings (SPF/DKIM strictness, subdomains)';
}

// Plain-English labels for the technical action values (deliver/quarantine/reject/none)
const actionLabels = {
  deliver:    "Delivered",
  quarantine: "Sent to Spam",
  reject:     "Blocked",
  none:       "No Action Taken"
};

// Builds a step-by-step breakdown of how a DMARC result was reached,
// from the raw evaluateDMARC() result object (r) and the email info (e).
// Used by both the Live Monitor and the "Test Your Own Email" feature.
function buildPipelineHTML(r, e) {
  e = e || {};
  const spfPass  = !!r.spfAligned;
  const dkimPass = !!r.dkimAligned;
  const verdictLabel = (actionLabels[r.action] || r.action || 'Unknown').toString();
  const verdictStatus = r.action === 'deliver' ? 'pass' : r.action === 'reject' ? 'fail' : 'warn';

  const steps = [
    {
      status: null, title: 'Email Received',
      desc: `From <strong>${e.from || r.fromDomain || 'unknown sender'}</strong>${e.subject ? `, subject "${e.subject}"` : ''}.`
    },
    {
      status: spfPass ? 'pass' : 'fail', title: 'SPF Check',
      desc: (r.alignmentDetails && r.alignmentDetails.spf) || 'SPF alignment could not be determined.'
    },
    {
      status: dkimPass ? 'pass' : 'fail', title: 'DKIM Check',
      desc: (r.alignmentDetails && r.alignmentDetails.dkim) || 'DKIM alignment could not be determined.'
    },
    {
      status: null, title: 'DMARC Policy Looked Up',
      desc: r.policy
        ? `${e.fromDomain || r.fromDomain || 'This domain'}'s DNS says: <strong>p=${r.policy}</strong>${r.pct !== undefined && r.pct !== 100 ? ` (applies to ${r.pct}% of mail)` : ''}.`
        : `No DMARC record was found for ${e.fromDomain || r.fromDomain || 'this domain'} — there is no policy to enforce.`
    },
    {
      status: verdictStatus, title: `Final Verdict: ${verdictLabel}`,
      desc: r.reason || ''
    }
  ];

  return renderPipelineSteps(steps);
}

// Shared renderer for any step list built by the buildXPipelineHTML functions —
// keeps the markup identical across the DMARC verdict, audit, and analyzer pipelines.
function renderPipelineSteps(steps) {
  return `<div class="pipeline">${steps.map((s, i) => `
    <div class="pipeline-step ${s.status || ''}">
      <div class="pipeline-num">${i + 1}</div>
      <div class="pipeline-body">
        <div class="pipeline-title">${s.title}${s.status ? `<span class="pipeline-tag ${s.status}">${s.status === 'pass' ? 'Passed' : s.status === 'fail' ? 'Failed' : s.status === 'warn' ? 'Warning' : 'Note'}</span>` : ''}</div>
        <div class="pipeline-desc">${s.desc}</div>
      </div>
    </div>
    ${i < steps.length - 1 ? '<div class="pipeline-connector"></div>' : ''}`).join('')}</div>`;
}

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
  document.getElementById("inline-comparison-trigger").style.display = "none";
  document.getElementById("inline-comparison").style.display = "none";

  detailCard.scrollIntoView({ behavior: "smooth", block: "start" });
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

  document.getElementById("verdict-text").textContent = (actionLabels[r.action] || r.action.toUpperCase()).toUpperCase();

  // Status chip
  const statusEl = document.getElementById("res-status");
  statusEl.textContent = r.status.toUpperCase();
  statusEl.className = "chip-value " + (r.status === "pass" ? "pass" : r.status === "error" ? "warn" : "fail");

  // Action chip
  const actionEl = document.getElementById("res-action");
  actionEl.textContent = (actionLabels[r.action] || r.action.toUpperCase()).toUpperCase();
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
  document.getElementById("spf-align-text").textContent  = "SPF: "  + (r.spfAligned  ? "Aligned" : "Not Aligned");
  document.getElementById("dkim-align-text").textContent = "DKIM: " + (r.dkimAligned ? "Aligned" : "Not Aligned");

  // Explanation — comes from scenarioService.js on the backend
  document.getElementById("explain-box").textContent = r.explanation || "";

  // Attack cost callout — show real world impact for failed/attack scenarios
  const costEl = document.getElementById("cost-callout");
  const costText = document.getElementById("cost-callout-text");
  if (costEl && costText) {
    const costs = {
      "basic-spoof":      "Phishing emails cost businesses an average of <strong>$136,000 per incident</strong> in 2023. A DMARC policy of p=reject would have blocked this email entirely before it reached anyone.",
      "ceo-fraud":        "CEO fraud (Business Email Compromise) is the most expensive cyber crime — costing businesses <strong>over $2.9 billion globally in 2023</strong>. p=quarantine reduces risk but only p=reject stops it completely.",
      "banking-phish":    "Banking phishing campaigns target thousands of customers at once. A single campaign can steal <strong>millions in credentials</strong>. Banks with p=reject protected their customers — those without did not.",
      "monitor-only":     "Having DMARC at p=none is like having a security camera with no alarm. You can see the attack happening but you cannot stop it. <strong>Most spoofing victims had DMARC configured but at p=none.</strong>",
      "spf-misalign":     "This attack bypasses SPF checks entirely — which is why <strong>SPF alone is not enough</strong>. DMARC closes this gap by checking that the visible From address also aligns. Without DMARC, this attack succeeds silently.",
      "subdomain-spoof":  "Subdomain attacks are harder to detect because the sending domain looks legitimate. <strong>One in three phishing emails uses a subdomain variation</strong> of a trusted brand.",
      "pct-50-fail":      "With pct=50, attackers have a <strong>50% chance of reaching the inbox</strong> on every attempt. For a campaign sending 10,000 emails, that means 5,000 attacks still succeed.",
    };
    const key = currentScenario;
    if (r.action !== "deliver" || r.status === "fail") {
      if (costs[key]) {
        costEl.style.display = "block";
        costText.innerHTML = costs[key];
      } else {
        costEl.style.display = "none";
      }
    } else {
      costEl.style.display = "none";
    }
  }

  // Step-by-step pipeline
  const s = scenarioMeta[currentScenario];
  const pipelineEmail = {
    from:       s ? `sender@${s.fromDomain}` : r.fromDomain,
    fromDomain: r.fromDomain,
    subject:    s ? s.name : ''
  };
  document.getElementById("scenario-pipeline").innerHTML = buildPipelineHTML(r, pipelineEmail);

  // The 4-policy comparison only has data for a handful of scenarios —
  // only offer it when there's actually something to show.
  const compareTrigger = document.getElementById("inline-comparison-trigger");
  compareTrigger.style.display = comparisonScenarios[currentScenario] ? "block" : "none";
  document.getElementById("inline-comparison").style.display = "none";
  document.getElementById("compare-btn").textContent = "See this scenario across all 4 DMARC policies";

  el.scrollIntoView({ behavior: "smooth", block: "start" });
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
        <div class="summary-label">High Risk<span class="info-tip" tabindex="0" data-tip="Emails scoring above 70 out of 100 on the risk scale — the ones most likely to be an attack."></span></div>
        <div class="summary-value fail">${s.highRisk}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Avg Risk Score</div>
        <div class="summary-value">${s.averageRiskScore}</div>
      </div>
    </div>

    <div class="summary-details">
      <div class="detail-section">
        <strong>By DMARC Policy:</strong>
        <div class="policy-breakdown">
          ${Object.entries(s.byPolicy).map(([p, c]) => `<div>${p.toUpperCase()}: ${c}</div>`).join("")}
        </div>
      </div>
      <div class="detail-section">
        <strong>By Outcome:</strong>
        <div class="action-breakdown">
          ${Object.entries(s.byAction).map(([a, c]) => `<div>${(actionLabels[a] || a.toUpperCase())}: ${c}</div>`).join("")}
        </div>
      </div>
    </div>

    <div class="button-group">
      <button class="btn-secondary" onclick="loadReportsList()">View All Reports</button>
      <button class="btn-secondary" onclick="exportReportsCSV()">Export as CSV</button>
      <button class="btn-secondary" onclick="clearReports()">Clear Reports</button>
    </div>
  `;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
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
      <td><span class="chip-value ${r.action === 'deliver' ? 'pass' : r.action === 'quarantine' ? 'warn' : 'fail'}">${actionLabels[r.action] || r.action}</span></td>
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

// Expand/collapse the inline 4-policy comparison beneath the current result,
// loading it on first expand.
function toggleInlineComparison() {
  const wrap = document.getElementById('inline-comparison');
  const btn  = document.getElementById('compare-btn');
  const isHidden = wrap.style.display === 'none' || !wrap.style.display;

  if (isHidden) {
    wrap.style.display = 'block';
    btn.textContent = 'Hide policy comparison';
    loadComparison(currentScenario);
  } else {
    wrap.style.display = 'none';
    btn.textContent = 'See this scenario across all 4 DMARC policies';
  }
}

// Run all four policy columns for the selected attack
async function loadComparison(key) {
  const s = comparisonScenarios[key];
  if (!s) return;

  // Show attack description
  const attackBox = document.getElementById("inline-attack-box");
  attackBox.style.display = "block";
  attackBox.textContent = s.attack;

  // Show loading state
  const grid = document.getElementById("inline-comparison-grid");
  const takeawayCard = document.getElementById("inline-takeaway-card");
  const loadingBar = document.getElementById("inline-loading-bar");
  const loadingText = document.getElementById("inline-loading-text");
  grid.style.display = "none";
  takeawayCard.style.display = "none";
  loadingText.style.display = "block";
  loadingText.textContent = "Running all four policy evaluations...";
  loadingBar.style.width = "0";
  void loadingBar.offsetWidth;
  loadingBar.style.width = "90%";
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

    loadingText.style.display = "none";
    grid.style.display = "grid";
    takeawayCard.style.display = "block";
    grid.style.animation = "none";
    void grid.offsetWidth;
    grid.style.animation = "fadeUp 0.4s ease both";
    grid.scrollIntoView({ behavior: "smooth", block: "start" });

  } catch (err) {
    loadingText.textContent = "Could not reach server. Make sure node app.js is running.";
    ['nodmarc','none','quarantine','reject'].forEach(id => {
      document.getElementById(`comp-col-${id}`).innerHTML = `<div class="error-box">Server error. Make sure node app.js is running.</div>`;
    });
    grid.style.display = "grid";
  }
}

function renderComparisonColumn(colId, r, description) {
  const riskColor  = r.riskScore <= 20 ? "pass" : r.riskScore <= 50 ? "warn" : "fail";

  document.getElementById(`comp-col-${colId}`).innerHTML = `
    <div class="comp-verdict ${r.action}">
      <span>${(actionLabels[r.action] || r.action.toUpperCase()).toUpperCase()}</span>
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
// SECTION 6 — LIVE EMAIL MONITOR TAB
// =============================================================

let monitorInterval = null;
let monitorActive   = false;
let lastSeenTime    = null;

function toggleMonitor() {
  if (monitorActive) { stopMonitor(); } else { startMonitor(); }
}

function startMonitor() {
  monitorActive = true;
  document.getElementById('monitor-btn-text').textContent    = 'Stop Monitor';
  document.getElementById('monitor-dot').style.background    = 'var(--pass)';
  document.getElementById('monitor-dot').style.boxShadow     = '0 0 6px var(--pass)';
  document.getElementById('monitor-status-text').textContent = 'Monitoring port 2525...';
  document.getElementById('monitor-status-text').style.color = 'var(--pass)';
  pollMonitor();
  monitorInterval = setInterval(pollMonitor, 3000);
}

function stopMonitor() {
  monitorActive = false;
  if (monitorInterval) { clearInterval(monitorInterval); monitorInterval = null; }
  document.getElementById('monitor-btn-text').textContent    = 'Start Monitor';
  document.getElementById('monitor-dot').style.background    = 'var(--muted)';
  document.getElementById('monitor-dot').style.boxShadow     = 'none';
  document.getElementById('monitor-status-text').textContent = 'Not monitoring';
  document.getElementById('monitor-status-text').style.color = 'var(--muted)';
}

async function pollMonitor() {
  try {
    const response = await fetch('/api/dmarc/smtp/latest');
    if (!response.ok) return;
    const result = await response.json();
    if (result.status === 'waiting' || !result.email) return;
    const receivedAt = result.email?.receivedAt;
    if (receivedAt === lastSeenTime) return;
    lastSeenTime = receivedAt;
    renderMonitorResult(result);
  } catch (err) {
    stopMonitor();
    document.getElementById('monitor-status-text').textContent = 'Cannot reach server';
    document.getElementById('monitor-status-text').style.color = 'var(--fail)';
  }
}

async function clearMonitor() {
  try { await fetch('/api/dmarc/smtp/latest', { method: 'DELETE' }); } catch (e) {}
  lastSeenTime = null;
  document.getElementById('monitor-result').style.display = 'none';
}

async function sendTestEmail(type) {
  if (!monitorActive) startMonitor();
  const el = document.getElementById('monitor-result');
  el.style.display = 'block';
  el.className     = 'card';
  el.innerHTML = `
    <div class="card-title">Latest Email Result</div>
    <div style="display:flex; align-items:center; gap:14px; padding:20px 0;">
      <div style="width:20px; height:20px; border-radius:50%; border:3px solid var(--border); border-top-color:var(--accent); animation:spin 0.8s linear infinite; flex-shrink:0;"></div>
      <div style="font-family:var(--mono); font-size:13px; color:var(--muted);">Sending email — waiting for DMARC evaluation...</div>
    </div>`;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  try { await fetch('/api/dmarc/smtp/latest', { method: 'DELETE' }); } catch (e) {}
  lastSeenTime = null;
  try {
    const response = await fetch('/api/dmarc/smtp/send-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    if (!response.ok) {
      el.innerHTML = `<div class="error-box">Could not send test email. Make sure node app.js is running.</div>`;
    }
  } catch (err) {
    el.innerHTML = `<div class="error-box">Could not reach server: ${err.message}</div>`;
  }
}

// renderMonitorResult — large visual banner showing deliver/quarantine/reject
function renderMonitorResult(r) {
  const el = document.getElementById('monitor-result');

  // Coloured top border on the card based on verdict
  el.className = 'card monitor-result-' + r.action;
  el.style.display = 'block';
  el.style.animation = 'none';
  void el.offsetWidth;
  el.style.animation = 'fadeUp 0.4s ease both';

  const e = r.email || {};
  const labels = { deliver: 'EMAIL DELIVERED', quarantine: 'SENT TO SPAM', reject: 'EMAIL BLOCKED' };

  el.innerHTML = `
    <div class="card-title">Latest Email Result</div>

    <div class="monitor-banner ${r.action}">
      <div class="monitor-banner-label">${labels[r.action] || r.action.toUpperCase()}</div>
      <div class="monitor-banner-reason">${r.reason || ''}</div>
    </div>

    <div style="background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:14px 16px; margin-bottom:16px; font-family:var(--mono); font-size:13px; line-height:1.8;">
      <span style="color:var(--muted);">From:</span>        ${e.from || 'unknown'}<br>
      <span style="color:var(--muted);">Subject:</span>     ${e.subject || '(no subject)'}<br>
      <span style="color:var(--muted);">From Domain:</span> ${e.fromDomain || 'unknown'}<br>
      <span style="color:var(--muted);">Envelope:<span class="info-tip" tabindex="0" data-tip="The actual sending address used behind the scenes — can be different from the From: address the recipient sees."></span></span> ${e.envelopeDomain || 'unknown'}<br>
      <span style="color:var(--muted);">DKIM Signed:<span class="info-tip" tabindex="0" data-tip="Whether the email carried a digital signature proving it wasn't altered in transit."></span></span> ${e.hasDKIM ? 'Yes (' + e.dkimDomain + ')' : 'No'}<br>
      <span style="color:var(--muted);">Received:</span>    ${e.receivedAt ? new Date(e.receivedAt).toLocaleTimeString() : 'unknown'}
    </div>

    <div class="result-details">
      <div class="detail-chip"><div class="chip-label">Status</div><div class="chip-value ${r.status === 'pass' ? 'pass' : 'fail'}">${r.status.toUpperCase()}</div></div>
      <div class="detail-chip"><div class="chip-label">Policy Applied</div><div class="chip-value">${(r.policy || 'N/A').toUpperCase()}</div></div>
      <div class="detail-chip"><div class="chip-label">Risk Score<span class="info-tip" tabindex="0" data-tip="A 0-100 score estimating how dangerous this email is. Higher means more suspicious."></span></div><div class="chip-value ${r.riskScore <= 20 ? 'pass' : r.riskScore <= 50 ? 'warn' : 'fail'}">${r.riskScore} / 100</div></div>
    </div>

    <div class="alignment-row">
      <div class="align-chip"><div class="align-dot ${r.spfAligned ? 'pass' : 'fail'}"></div><span>SPF: ${r.spfAligned ? 'Aligned' : 'Not Aligned'}</span><span class="info-tip" tabindex="0" data-tip="SPF checks whether the email came from a server the domain owner approved. Aligned means yes, this is a trusted server."></span></div>
      <div class="align-chip"><div class="align-dot ${r.dkimAligned ? 'pass' : 'fail'}"></div><span>DKIM: ${r.dkimAligned ? 'Aligned' : 'Not Aligned'}</span><span class="info-tip" tabindex="0" data-tip="DKIM is a digital signature on the email proving it wasn't altered and really came from who it claims. Aligned means the signature checks out."></span></div>
    </div>

    <div class="card-title" style="margin-top:20px;">Step-by-Step: How DMARC Reached This Verdict</div>
    ${buildPipelineHTML(r, e)}`;

  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// =============================================================
// SECTION 7 — DMARC RECORD GENERATOR
// Pure frontend — no backend needed
// Builds a valid DMARC TXT record from user inputs
// =============================================================

function generateRecord() {
  const domain = document.getElementById('gen-domain').value.trim();
  const policy = document.getElementById('gen-policy').value;
  const sp     = document.getElementById('gen-sp').value;
  const pct    = document.getElementById('gen-pct').value;
  const aspf   = document.getElementById('gen-aspf').value;
  const adkim  = document.getElementById('gen-adkim').value;
  const rua    = document.getElementById('gen-rua').value.trim();
  const ruf    = document.getElementById('gen-ruf').value.trim();

  if (!domain) { alert('Please enter a domain name.'); return; }

  // Build the record tag by tag
  let record = `v=DMARC1; p=${policy}`;
  if (sp)               record += `; sp=${sp}`;
  if (rua)              record += `; rua=mailto:${rua}`;
  if (ruf)              record += `; ruf=mailto:${ruf}`;
  if (pct !== '100')    record += `; pct=${pct}`;
  if (aspf !== 'r')     record += `; aspf=${aspf}`;
  if (adkim !== 'r')    record += `; adkim=${adkim}`;

  // Show result card
  const el = document.getElementById('gen-result');
  el.style.display = 'block';
  el.style.animation = 'none';
  void el.offsetWidth;
  el.style.animation = 'fadeUp 0.4s ease both';

  // Show the record string
  document.getElementById('gen-record-output').textContent = record;

  // DNS name instruction
  document.getElementById('gen-dns-name').textContent = `_dmarc.${domain}`;

  // Tag breakdown chips
  const policyColor = policy === 'reject' ? 'good' : policy === 'quarantine' ? 'warn' : 'bad';
  const pctColor    = pct === '100' ? 'good' : parseInt(pct) >= 50 ? 'warn' : 'bad';
  const ruaColor    = rua ? 'good' : 'bad';

  document.getElementById('gen-tag-breakdown').innerHTML = `
    <div class="audit-tag"><div class="audit-tag-key">p= (policy)</div><div class="audit-tag-value ${policyColor}">${policy}</div></div>
    <div class="audit-tag"><div class="audit-tag-key">sp= (subdomains)</div><div class="audit-tag-value ${sp ? 'good' : 'muted'}">${sp || 'inherit'}</div></div>
    <div class="audit-tag"><div class="audit-tag-key">pct= (enforcement)</div><div class="audit-tag-value ${pctColor}">${pct}%</div></div>
    <div class="audit-tag"><div class="audit-tag-key">rua= (reports)</div><div class="audit-tag-value ${ruaColor}">${rua ? 'configured' : 'not set'}</div></div>
    <div class="audit-tag"><div class="audit-tag-key">aspf= (SPF align)</div><div class="audit-tag-value">${aspf === 'r' ? 'relaxed' : 'strict'}</div></div>
    <div class="audit-tag"><div class="audit-tag-key">adkim= (DKIM align)</div><div class="audit-tag-value">${adkim === 'r' ? 'relaxed' : 'strict'}</div></div>
  `;

  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// copyRecord — copies the generated record to clipboard
function copyRecord() {
  const record = document.getElementById('gen-record-output').textContent;
  navigator.clipboard.writeText(record).then(() => {
    const btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied';
    btn.style.color = 'var(--pass)';
    btn.style.borderColor = 'var(--pass)';
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.style.color = '';
      btn.style.borderColor = '';
    }, 2000);
  });
}


// =============================================================
// SECTION 8 — DNS PROPAGATION CHECKER
// Calls GET /api/dmarc/propagation/:domain
// Queries 4 public DNS resolvers and compares results
// =============================================================

function loadPropDomain(domain) {
  document.getElementById('prop-domain').value = domain;
  document.querySelectorAll('#tab-propagation .scenario-btn').forEach(b => {
    b.style.borderColor = ''; b.style.color = '';
  });
  event.currentTarget.style.borderColor = 'var(--accent)';
  event.currentTarget.style.color       = 'var(--accent)';
  document.getElementById('prop-result').style.display = 'none';
}

async function checkPropagation() {
  const domain = document.getElementById('prop-domain').value.trim();
  if (!domain) { alert('Please enter a domain name.'); return; }

  // Show loading state
  const el = document.getElementById('prop-result');
  el.style.display = 'block';
  el.innerHTML = `
    <div class="card-title">Propagation Results</div>
    <div style="display:flex; align-items:center; gap:14px; padding:20px 0;">
      <div style="width:20px; height:20px; border-radius:50%; border:3px solid var(--border); border-top-color:var(--accent); animation:spin 0.8s linear infinite; flex-shrink:0;"></div>
      <div style="font-family:var(--mono); font-size:13px; color:var(--muted);">Querying DNS resolvers for ${domain}...</div>
    </div>`;

  try {
    const response = await fetch(`/api/dmarc/propagation/${encodeURIComponent(domain)}`);
    if (!response.ok) throw new Error('Server error: ' + response.status);
    const data = await response.json();
    renderPropagationResult(data);
  } catch (err) {
    el.innerHTML = `<div class="error-box">Could not check propagation: ${err.message}. Make sure node app.js is running.</div>`;
  }
}

function renderPropagationResult(data) {
  const el = document.getElementById('prop-result');
  el.style.display = 'block';
  el.style.animation = 'none';
  void el.offsetWidth;
  el.style.animation = 'fadeUp 0.4s ease both';

  const s = data.summary;

  // Status colours and labels
  const statusConfig = {
    FULLY_PROPAGATED:      { color: 'var(--pass)', label: 'Fully Propagated', desc: `Your DMARC record has propagated to all ${s.total} resolvers and they all agree.` },
    PARTIALLY_PROPAGATED:  { color: 'var(--warn)', label: 'Partially Propagated', desc: `Found on ${s.found} of ${s.total} resolvers. Propagation is still in progress — check again in a few hours.` },
    INCONSISTENT:          { color: 'var(--warn)', label: 'Inconsistent', desc: 'Different resolvers are returning different records. DNS caching may cause this — wait a few hours.' },
    NOT_PROPAGATED:        { color: 'var(--fail)', label: 'Not Propagated', desc: 'No resolvers found a DMARC record. Either the record has not been published yet or it has not propagated.' },
  };

  const cfg = statusConfig[s.propagationStatus] || statusConfig.NOT_PROPAGATED;

  el.innerHTML = `
    <div class="card-title">Propagation Results — ${data.domain}</div>

    <!-- Overall status banner -->
    <div style="background:rgba(0,0,0,0.2); border:1px solid ${cfg.color}; border-radius:10px; padding:20px; margin-bottom:20px; display:flex; align-items:center; gap:16px;">
      <div>
        <div style="font-family:var(--mono); font-size:16px; font-weight:700; color:${cfg.color}; margin-bottom:4px;">${cfg.label}</div>
        <div style="font-size:13px; color:var(--muted);">${cfg.desc}</div>
      </div>
      <div style="margin-left:auto; text-align:center; flex-shrink:0;">
        <div style="font-family:var(--mono); font-size:28px; font-weight:700; color:${cfg.color};">${s.found}/${s.total}</div>
        <div style="font-family:var(--mono); font-size:10px; color:var(--muted); text-transform:uppercase;">Resolvers Found</div>
      </div>
    </div>

    <!-- Per-resolver results -->
    <div style="display:flex; flex-direction:column; gap:10px; margin-bottom:16px;">
      ${data.results.map(r => {
        const statusColor = r.status === 'found' ? 'var(--pass)' : r.status === 'timeout' ? 'var(--warn)' : 'var(--fail)';
        const statusLabel = r.status === 'found' ? 'FOUND' : r.status === 'timeout' ? 'TIMEOUT' : 'NOT FOUND';
        return `
          <div style="background:var(--surface2); border:1px solid var(--border); border-left:3px solid ${statusColor}; border-radius:8px; padding:14px 16px;">
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:${r.record ? '8px' : '0'};">
              <div style="flex:1;">
                <span style="font-family:var(--mono); font-weight:700; color:var(--text);">${r.resolver}</span>
                <span style="font-family:var(--mono); font-size:11px; color:var(--muted); margin-left:8px;">${r.ip}</span>
              </div>
              <span style="font-family:var(--mono); font-size:11px; font-weight:700; color:${statusColor};">${statusLabel}</span>
            </div>
            ${r.record ? `<div style="font-family:var(--mono); font-size:11px; color:var(--accent); background:var(--surface); padding:8px 10px; border-radius:6px; word-break:break-all;">${r.record}</div>` : ''}
            ${r.error  ? `<div style="font-family:var(--mono); font-size:11px; color:var(--warn);">${r.error}</div>` : ''}
          </div>`;
      }).join('')}
    </div>

    <!-- Consistency note -->
    ${s.uniqueRecords.length > 1 ? `
      <div style="background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.3); border-radius:8px; padding:14px 16px;">
        <div style="font-family:var(--mono); font-size:11px; font-weight:700; color:var(--warn); text-transform:uppercase; margin-bottom:8px;">Inconsistent Records Detected</div>
        <div style="font-size:13px; color:var(--text);">Different resolvers returned different records. This usually means DNS propagation is still in progress. Wait a few hours and check again.</div>
      </div>` : ''}

    <div style="font-family:var(--mono); font-size:11px; color:var(--muted); margin-top:12px; text-align:right;">
      Checked at ${new Date(data.checkedAt).toLocaleTimeString()}
    </div>`;

  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// =============================================================
// SECTION 9 — TEST YOUR OWN EMAIL
// Calls POST /api/dmarc/test-email — either a raw pasted email
// (mode: 'raw') or just the sender details (mode: 'simple')
// =============================================================

function setTestEmailMode(mode) {
  const rawBtn        = document.getElementById('test-mode-btn-raw');
  const simpleBtn      = document.getElementById('test-mode-btn-simple');
  const rawSection     = document.getElementById('test-email-raw-section');
  const simpleSection  = document.getElementById('test-email-simple-section');

  if (mode === 'raw') {
    rawSection.style.display = 'block'; simpleSection.style.display = 'none';
    rawBtn.style.borderColor = 'var(--accent)'; rawBtn.style.color = 'var(--accent)';
    simpleBtn.style.borderColor = ''; simpleBtn.style.color = '';
  } else {
    rawSection.style.display = 'none'; simpleSection.style.display = 'block';
    simpleBtn.style.borderColor = 'var(--accent)'; simpleBtn.style.color = 'var(--accent)';
    rawBtn.style.borderColor = ''; rawBtn.style.color = '';
  }
  document.getElementById('test-email-result').innerHTML = '';
}

// Constructed example raw emails — genuine phishing samples online are
// almost always screenshots with no underlying headers attached, so
// these give something realistic to test with right away.
const emailExamples = {
  phish:
`From: "DBS Bank Security" <security@dbs.com.sg>
Return-Path: <bounce@dbs-alert-secure.net>
Received: from mail.dbs-alert-secure.net (198.51.100.24) by mx.example.com; Wed, 5 Aug 2026 09:12:44 +0000
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=dbs-alert-secure.net; dkim=none
Subject: URGENT: Unusual login detected - verify your account
Date: Wed, 5 Aug 2026 09:12:44 +0000
Message-ID: <9f2a@dbs-alert-secure.net>

Dear Customer, we detected unusual activity on your DBS account. Click here immediately to verify your identity or your account will be suspended within 24 hours.`,

  legit:
`From: GitHub <notifications@github.com>
Return-Path: <bounce+abc123@github.com>
Received: from o1.mail.github.com (192.0.2.55) by mx.example.com; Wed, 5 Aug 2026 14:03:10 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=github.com; s=pf2023; c=relaxed/relaxed; h=from:subject:date; bh=abc123; b=validsignaturehere
Subject: [GitHub] New sign-in to your account
Date: Wed, 5 Aug 2026 14:03:10 +0000
Message-ID: <abc123@github.com>

We noticed a new sign-in to your GitHub account from a new device. If this was you, no action is required.`
};

function loadEmailExample(key) {
  const raw = emailExamples[key];
  if (!raw) return;
  document.getElementById('test-email-raw').value = raw;
  document.querySelectorAll('#test-email-raw-section .scenario-btn').forEach(b => { b.style.borderColor = ''; b.style.color = ''; });
  event.currentTarget.style.borderColor = 'var(--accent)';
  event.currentTarget.style.color = 'var(--accent)';
  document.getElementById('test-email-result').innerHTML = '';
}

async function testRawEmail() {
  const raw = document.getElementById('test-email-raw').value.trim();
  const resultEl = document.getElementById('test-email-result');
  if (!raw) { alert('Paste the raw email source first.'); return; }

  resultEl.innerHTML = '<div style="display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:13px;color:var(--muted);"><div style="width:16px;height:16px;border-radius:50%;border:2px solid var(--border);border-top-color:var(--accent);animation:spin 0.8s linear infinite;"></div>Checking headers against live DNS...</div>';
  resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

  try {
    const response = await fetch('/api/dmarc/test-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'raw', rawSource: raw })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not analyse this email');

    renderTestEmailRawResult(data);
  } catch (err) {
    resultEl.innerHTML = `<div class="error-box">${err.message}</div>`;
  }
}

// Builds concrete next-action guidance for a raw-header DMARC evaluation —
// turns a verdict into "what do I actually do now" rather than just an explanation.
function buildNextStepsHTML(r, hasEvidence) {
  const items = [];

  if (!hasEvidence) {
    items.push("SPF couldn't be checked from what was pasted — get the full raw source (headers included, not just the visible message) from your email client for a real check, or confirm with the sender through a separate, already-known channel before trusting it.");
  } else if (r.status === 'fail') {
    items.push("This failed DMARC — treat it as suspicious. Don't click any links, reply, or enter any information.");
    items.push('Report it to your IT/security team, or use your email client\'s "Report Phishing" option, then delete it.');
    if (r.action === 'deliver') {
      items.push(`This domain's DMARC policy is weak (p=${r.policy || 'none'}), so a real attacker's copy of this would likely have reached the inbox unblocked — worth flagging to whoever manages this domain's email security.`);
    }
  } else {
    items.push("SPF/DKIM aligned with the sender domain — structurally this looks like it came from where it claims to.");
    items.push("That only confirms authentication, not intent. If it asks for money, credentials, or urgent action, verify through a separate, known channel before acting on it.");
  }

  items.push("This check covers DMARC/SPF/DKIM only — it doesn't scan links, attachments, or wording for malicious content.");

  return `
    <div class="card-title" style="margin-top:20px;">Recommended Next Steps</div>
    <div style="display:flex; flex-direction:column; gap:8px;">
      ${items.map(i => `<div class="audit-rec">${i}</div>`).join('')}
    </div>`;
}

// Same idea for the "basic details" heuristic check
function buildSimpleNextStepsHTML(r) {
  const items = [];
  if (r.claimedDomain === null) {
    items.push('Add the real company\'s domain above to check whether this sender is a lookalike.');
  } else if (r.domainsMatch) {
    items.push('The domain matches, but that alone doesn\'t prove the email is genuine. Use "Paste Raw Email" with the full headers for a real authentication check.');
    items.push("If it asks for money, credentials, or urgent action, verify through a separate, known channel first.");
  } else {
    items.push("This did not come from the real company's domain. Don't click any links, reply, or enter any information.");
    items.push('Report it to your IT/security team or your email provider\'s phishing report option, then delete it.');
  }
  return `
    <div class="card-title" style="margin-top:16px;">Recommended Next Steps</div>
    <div style="display:flex; flex-direction:column; gap:8px;">
      ${items.map(i => `<div class="audit-rec">${i}</div>`).join('')}
    </div>`;
}

function renderTestEmailRawResult(r) {
  const resultEl = document.getElementById('test-email-result');
  const e = r.email || {};
  const labels = { deliver: 'WOULD BE DELIVERED', quarantine: 'WOULD BE SENT TO SPAM', reject: 'WOULD BE BLOCKED' };

  const evidenceNote = r.hasEnvelopeEvidence
    ? `Found a Return-Path / Authentication-Results header, so SPF could be checked structurally against it.`
    : `No Return-Path or Authentication-Results header was found in what you pasted, so SPF could not be checked — it's being treated as unverifiable, not assumed to pass. Paste the full raw source (not just the visible message) for a real check.`;

  resultEl.innerHTML = `
    <div class="monitor-banner ${r.action}">
      <div class="monitor-banner-label">${labels[r.action] || (actionLabels[r.action] || r.action || '').toUpperCase()}</div>
      <div class="monitor-banner-reason">${r.reason || ''}</div>
    </div>

    <div style="background:rgba(56,189,248,0.05); border:1px solid rgba(56,189,248,0.15); border-radius:8px; padding:10px 14px; margin-bottom:16px; font-size:12px; color:var(--muted); line-height:1.5;">
      ${evidenceNote} This checks structure (sender vs. envelope domain, whether a DKIM signature exists) rather than cryptographically re-verifying the signature — the same approach used by the Live Monitor above.
    </div>

    <div style="background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:14px 16px; margin-bottom:16px; font-family:var(--mono); font-size:13px; line-height:1.8;">
      <span style="color:var(--muted);">From:</span> ${e.from || 'unknown'}<br>
      <span style="color:var(--muted);">Subject:</span> ${e.subject || '(no subject)'}<br>
      <span style="color:var(--muted);">From Domain:</span> ${e.fromDomain || 'unknown'}<br>
      <span style="color:var(--muted);">Envelope:</span> ${r.hasEnvelopeEvidence ? (e.envelopeDomain || 'unknown') : 'not found in pasted headers'}<br>
      <span style="color:var(--muted);">DKIM Signed:</span> ${e.hasDKIM ? 'Yes (' + e.dkimDomain + ')' : 'No signature found'}
    </div>

    <div class="card-title">Step-by-Step: How We Got This Result</div>
    ${buildPipelineHTML(r, e)}
    ${buildNextStepsHTML(r, r.hasEnvelopeEvidence)}`;

  resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function testSimpleEmail() {
  const fromAddress    = document.getElementById('test-email-from').value.trim();
  const claimedDomain  = document.getElementById('test-email-claimed-domain').value.trim();
  const resultEl = document.getElementById('test-email-result');
  if (!fromAddress || !fromAddress.includes('@')) { alert('Enter the sender email address, e.g. security@paypal.com'); return; }

  resultEl.innerHTML = '<div style="display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:13px;color:var(--muted);"><div style="width:16px;height:16px;border-radius:50%;border:2px solid var(--border);border-top-color:var(--accent);animation:spin 0.8s linear infinite;"></div>Checking...</div>';
  resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

  try {
    const response = await fetch('/api/dmarc/test-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'simple', fromAddress, claimedDomain })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not check this sender');

    renderTestEmailSimpleResult(data);
  } catch (err) {
    resultEl.innerHTML = `<div class="error-box">${err.message}</div>`;
  }
}

function renderTestEmailSimpleResult(r) {
  const resultEl = document.getElementById('test-email-result');
  const audit = r.officialDomainAudit;

  let matchLine;
  if (r.claimedDomain === null) {
    matchLine = `<div class="reason-box">We only have the sender address (<strong>${r.fromDomain}</strong>). Add the real company domain above for a lookalike check.</div>`;
  } else if (r.domainsMatch) {
    matchLine = `<div class="reason-box" style="border-left-color:var(--pass);">The sender domain exactly matches <strong>${r.claimedDomain}</strong> — no domain mismatch detected. (This alone doesn't prove the email is genuine — the full headers would be needed for that.)</div>`;
  } else if (r.lookalikeWarning) {
    matchLine = `<div class="reason-box" style="border-left-color:var(--fail);"><strong>${r.fromDomain}</strong> looks very similar to <strong>${r.claimedDomain}</strong> but is not the same domain — a classic lookalike-domain trick.</div>`;
  } else {
    matchLine = `<div class="reason-box" style="border-left-color:var(--fail);"><strong>${r.fromDomain}</strong> does not match ${r.claimedDomain}'s official domain at all — this did not come from the real company's mail system.</div>`;
  }

  resultEl.innerHTML = `
    <div style="background:rgba(251,191,36,0.06); border:1px solid rgba(251,191,36,0.2); border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:13px; color:var(--text);">
      This is a best-effort check based only on the sender address — without the full email headers we can't verify SPF/DKIM/DMARC directly. For a real verdict, use "Paste Raw Email" instead.
    </div>
    ${matchLine}
    ${audit ? `
      <div class="card-title" style="margin-top:16px;">${r.claimedDomain || r.fromDomain}'s Real DMARC Protection</div>
      <div style="display:flex; align-items:center; gap:16px; margin-bottom:12px;">
        <div class="grade-${audit.grade}" style="width:56px; height:56px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-family:var(--mono); font-size:28px; font-weight:700; flex-shrink:0;">${audit.grade}</div>
        <div style="font-size:14px; color:var(--text); line-height:1.5;">${audit.gradeDescription || ''}</div>
      </div>` : ''}
    ${buildSimpleNextStepsHTML(r)}`;

  resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}