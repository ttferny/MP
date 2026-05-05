// Pre-built scenarios
const scenarios = {
  "legit-spf":        { spfStatus: "pass", spfDomain: "legitbank.com", dkimStatus: "fail", dkimDomain: "",               policy: "reject",     pct: 100, from: "legitbank.com" },
  "legit-dkim":       { spfStatus: "fail", spfDomain: "",              dkimStatus: "pass", dkimDomain: "legitbank.com",   policy: "reject",     pct: 100, from: "legitbank.com" },
  "spoof-reject":     { spfStatus: "fail", spfDomain: "evil.com",      dkimStatus: "fail", dkimDomain: "evil.com",        policy: "reject",     pct: 100, from: "legitbank.com" },
  "spoof-quarantine": { spfStatus: "fail", spfDomain: "evil.com",      dkimStatus: "fail", dkimDomain: "evil.com",        policy: "quarantine", pct: 100, from: "legitbank.com" },
  "spoof-none":       { spfStatus: "fail", spfDomain: "evil.com",      dkimStatus: "fail", dkimDomain: "evil.com",        policy: "none",       pct: 100, from: "legitbank.com" },
  "misaligned":       { spfStatus: "pass", spfDomain: "evil.com",      dkimStatus: "fail", dkimDomain: "",                policy: "reject",     pct: 100, from: "legitbank.com" },
};

// Load a scenario into the form fields
function loadScenario(key) {
  const s = scenarios[key];
  if (!s) return;
  document.getElementById("spf-status").value  = s.spfStatus;
  document.getElementById("spf-domain").value   = s.spfDomain;
  document.getElementById("dkim-status").value  = s.dkimStatus;
  document.getElementById("dkim-domain").value  = s.dkimDomain;
  document.getElementById("dmarc-policy").value = s.policy;
  document.getElementById("dmarc-pct").value    = s.pct;
  document.getElementById("from-domain").value  = s.from;
}

// Read form values and call the backend
async function runDMARC() {
  const spf = {
    status: document.getElementById("spf-status").value,
    domain: document.getElementById("spf-domain").value.trim()
  };

  const dkim = {
    status: document.getElementById("dkim-status").value,
    domain: document.getElementById("dkim-domain").value.trim()
  };

  const parsed = {
    policy:     document.getElementById("dmarc-policy").value,
    pct:        parseInt(document.getElementById("dmarc-pct").value) || 100,
    fromDomain: document.getElementById("from-domain").value.trim()
  };

  try {
    const response = await fetch("/api/dmarc/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ spf, dkim, parsed })
    });

    if (!response.ok) throw new Error("Server error: " + response.status);

    const result = await response.json();
    renderResult(result);

  } catch (err) {
    console.error("Evaluation failed:", err);
    renderResult({
      status: "error",
      action: "none",
      reason: "Could not reach server. Is it running?",
      policy: "N/A",
      pct: 0,
      spfAligned: false,
      dkimAligned: false
    });
  }
}

// Render the result card
function renderResult(r) {
  const el = document.getElementById("result");
  el.style.display = "block";
  el.style.animation = "none";
  void el.offsetWidth; // force reflow to restart animation
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

  // Reason
  document.getElementById("res-reason").textContent = r.reason;

  // Alignment dots
  const spfDot  = document.getElementById("spf-dot");
  const dkimDot = document.getElementById("dkim-dot");
  spfDot.className  = "align-dot " + (r.spfAligned  ? "pass" : "fail");
  dkimDot.className = "align-dot " + (r.dkimAligned ? "pass" : "fail");

  document.getElementById("spf-align-text").textContent  = "SPF: "  + (r.spfAligned  ? "Aligned ✓" : "Not Aligned ✗");
  document.getElementById("dkim-align-text").textContent = "DKIM: " + (r.dkimAligned ? "Aligned ✓" : "Not Aligned ✗");
}
