const evaluateDMARC = (spf, dkim, parsed) => {

  // Check inputs exist
  if (!spf || !dkim) {
    return { status: "error", action: "none", reason: "Missing SPF or DKIM result" };
  }

  if (!parsed || !parsed.policy) {
    return { status: "error", action: "none", reason: "No DMARC record found" };
  }

  const { policy, fromDomain, pct = 100 } = parsed;

  // Check if SPF or DKIM domain matches the sender domain
  const spfAligned  = spf.status  === "pass" && spf.domain  === fromDomain;
  const dkimAligned = dkim.status === "pass" && dkim.domain === fromDomain;

  // If either aligns, email is legitimate
  if (spfAligned || dkimAligned) {
    return {
      status: "pass",
      action: "deliver",
      reason: `DMARC passed via ${spfAligned ? "SPF" : "DKIM"} alignment`,
      policy,
      pct
    };
  }

  // Both failed — apply the domain's policy
  const actions = {
    "none":       { action: "deliver",    reason: "Policy is none — monitoring only" },
    "quarantine": { action: "quarantine", reason: "Email flagged as suspicious" },
    "reject":     { action: "reject",     reason: "Email rejected by DMARC policy" }
  };

  const outcome = actions[policy] ?? { action: "quarantine", reason: "Unknown policy, defaulting to quarantine" };

  return { status: "fail", policy, pct, ...outcome };
};

module.exports = { evaluateDMARC };