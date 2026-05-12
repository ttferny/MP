// Zircon — DMARC Record Auditor
// Analyses a raw DMARC TXT record string and grades the domain's
// DMARC configuration against email security best practices.
//
// Scope: DMARC tags only (p=, sp=, pct=, rua=, ruf=, aspf=, adkim=)
// DNS lookup is Ashton's responsibility — this service receives the
// raw record string as input and does not make any DNS calls.


// ─────────────────────────────────────────────────────────────
// DMARC TAG PARSER
// Converts a raw DMARC TXT record string into a structured object
// Input:  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
// Output: { policy: "reject", rua: "mailto:...", pct: 100, ... }
// ─────────────────────────────────────────────────────────────

const parseDMARCRecord = (record) => {
  if (!record) return null;

  const tags = {};

  record.split(';').forEach(part => {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) return;

    const key   = part.slice(0, eqIndex).trim();
    const value = part.slice(eqIndex + 1).trim();
    if (key) tags[key] = value;
  });

  return {
    version: tags['v']    || null,
    policy:  tags['p']    || null,       // p=  — main domain policy
    sp:      tags['sp']   || null,       // sp= — subdomain policy
    pct:     parseInt(tags['pct']) || 100, // pct= — enforcement percentage
    rua:     tags['rua']  || null,       // rua= — aggregate report URI
    ruf:     tags['ruf']  || null,       // ruf= — forensic report URI
    aspf:    tags['aspf'] || 'r',        // aspf= — SPF alignment mode (r=relaxed, s=strict)
    adkim:   tags['adkim'] || 'r',       // adkim= — DKIM alignment mode (r=relaxed, s=strict)
    raw:     record
  };
};


// ─────────────────────────────────────────────────────────────
// DMARC AUDITOR
// Grades a domain's DMARC configuration on a 0–100 scale
// and returns specific issues and recommendations.
//
// Grading:
//   A — 90–100  Strong DMARC configuration
//   B — 75–89   Good but minor improvements possible
//   C — 60–74   Moderate — enforcement not at maximum
//   D — 40–59   Weak — policy present but misconfigured
//   F — 0–39    Critical — no DMARC or completely ineffective
// ─────────────────────────────────────────────────────────────

const auditDMARC = (dmarcRaw, domain) => {
  const issues          = [];
  const recommendations = [];
  let score             = 100;

  // ── No DMARC record ─────────────────────────────────────────
  if (!dmarcRaw) {
    issues.push("No DMARC record found for this domain");
    recommendations.push("Publish a DMARC record in DNS. Start with p=none to monitor your mail flow before enforcing.");
    recommendations.push("Example record: v=DMARC1; p=none; rua=mailto:dmarc@" + domain);

    return {
      domain,
      score: 0,
      grade: 'F',
      dmarc: null,
      issues,
      recommendations,
      auditedAt: new Date().toISOString()
    };
  }

  const dmarc = parseDMARCRecord(dmarcRaw);

  // ── Policy strength checks (p=) ─────────────────────────────
  if (!dmarc.policy) {
    issues.push("DMARC record is missing the required p= tag");
    recommendations.push("Add p=none, p=quarantine, or p=reject to your DMARC record");
    return {
      domain, score: 0, grade: 'F',
      gradeDescription: 'Critical. No DMARC record or policy is completely ineffective.',
      dmarc, issues, recommendations,
      auditedAt: new Date().toISOString()
    };
  }

  // ── Policy strength checks (p=) ─────────────────────────────
  if (dmarc.policy === 'none') {
    issues.push("p=none — DMARC is in monitoring mode only with no enforcement");
    recommendations.push("Upgrade to p=quarantine once you have confirmed legitimate mail flow via rua= reports");
    score -= 30;
  } else if (dmarc.policy === 'quarantine') {
    issues.push("p=quarantine — spoofed emails are moved to spam but still reach the recipient");
    recommendations.push("Consider upgrading to p=reject for full protection once mail flow is stable");
    score -= 10;
  }
  // p=reject is best practice — no deduction

  // ── Subdomain policy (sp=) ───────────────────────────────────
  if (!dmarc.sp) {
    // Subdomains inherit the main policy — only flag if main policy is weak
    if (dmarc.policy === 'none' || dmarc.policy === 'quarantine') {
      issues.push("No subdomain policy (sp=) — subdomains inherit the weak main policy");
      recommendations.push("Add sp=reject to explicitly protect subdomains from spoofing attacks");
      score -= 5;
    }
  } else if (dmarc.sp === 'none') {
    issues.push("sp=none — subdomains are in monitoring mode and not protected from spoofing");
    recommendations.push("Upgrade sp= to quarantine or reject to protect your subdomains");
    score -= 10;
  }

  // ── Enforcement percentage (pct=) ───────────────────────────
  if (dmarc.pct < 100) {
    if (dmarc.pct <= 25) {
      issues.push(`pct=${dmarc.pct} — policy applies to only ${dmarc.pct}% of failing emails. Most spoofed emails slip through.`);
      score -= 30;
    } else if (dmarc.pct <= 50) {
      issues.push(`pct=${dmarc.pct} — policy applies to ${dmarc.pct}% of failing emails. Half of spoofed emails are not enforced.`);
      score -= 20;
    } else {
      issues.push(`pct=${dmarc.pct} — policy does not apply to all failing emails`);
      score -= 10;
    }
    recommendations.push(`Increase pct to 100 to enforce the DMARC policy on all failing emails`);
  }

  // ── Aggregate reporting (rua=) ───────────────────────────────
  if (!dmarc.rua) {
    issues.push("No aggregate report URI (rua=) configured — you are not receiving DMARC reports");
    recommendations.push("Add rua=mailto:dmarc@" + domain + " to receive aggregate reports and monitor your mail flow");
    score -= 10;
  }

  // ── Alignment mode checks (aspf=, adkim=) ───────────────────
  if (dmarc.aspf === 's') {
    issues.push("aspf=s (strict SPF alignment) — legitimate emails from subdomains may fail SPF alignment");
    recommendations.push("Consider aspf=r (relaxed) unless strict alignment is specifically required");
    score -= 5;
  }

  if (dmarc.adkim === 's') {
    issues.push("adkim=s (strict DKIM alignment) — DKIM signatures from subdomains will not align");
    recommendations.push("Consider adkim=r (relaxed) to allow legitimate subdomain senders to pass DKIM alignment");
    score -= 5;
  }

  // ── Forensic reporting (ruf=) — optional bonus ──────────────
  // ruf= is optional but adds visibility for incident response
  // No score deduction — just informational

  // ── Final grade ─────────────────────────────────────────────
  const finalScore = Math.max(0, score);

  const grade =
    finalScore >= 90 ? 'A' :
    finalScore >= 75 ? 'B' :
    finalScore >= 60 ? 'C' :
    finalScore >= 40 ? 'D' : 'F';

  // ── Grade description ────────────────────────────────────────
  const gradeDescriptions = {
    A: "Strong DMARC configuration. The domain is well protected against email spoofing.",
    B: "Good configuration with minor improvements possible.",
    C: "Moderate configuration. Policy is present but not at maximum enforcement.",
    D: "Weak configuration. DMARC exists but has significant gaps in protection.",
    F: "Critical. No DMARC record or policy is completely ineffective."
  };

  return {
    domain,
    score:            finalScore,
    grade,
    gradeDescription: gradeDescriptions[grade],
    dmarc,
    issues,
    recommendations,
    auditedAt:        new Date().toISOString()
  };
};


module.exports = { auditDMARC, parseDMARCRecord };