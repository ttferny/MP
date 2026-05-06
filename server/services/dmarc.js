// Zircon

const evaluateDMARC = (spf, dkim, parsed) => {

  if (!spf || !dkim) {
    return { status: "error", action: "none", reason: "Missing SPF or DKIM result" };
  }

  if (!parsed || !parsed.policy) {
    return { status: "error", action: "none", reason: "No DMARC record found" };
  }

  const { policy, fromDomain, pct = 100, aspf = "r", adkim = "r", sp = null } = parsed;

  const spfAligned  = checkAlignment(spf.status,  spf.domain,  fromDomain, aspf);
  const dkimAligned = checkAlignment(dkim.status, dkim.domain, fromDomain, adkim);

  if (spfAligned || dkimAligned) {
    const riskScore = calculateRiskScore(true, policy, pct, spf.status, dkim.status);
    return {
      status: "pass",
      action: "deliver",
      reason: `DMARC passed via ${spfAligned ? "SPF" : "DKIM"} alignment (${spfAligned ? aspf : adkim} mode)`,
      policy, pct, aspf, adkim, sp, spfAligned, dkimAligned, riskScore,
      fromDomain  // ← add this
    };
  }

  const effectivePolicy = determineEffectivePolicy(spf.domain, dkim.domain, fromDomain, policy, sp);
  const actions = {
    "none":       { action: "deliver",    reason: "Policy is none — monitoring only" },
    "quarantine": { action: "quarantine", reason: "Email flagged as suspicious" },
    "reject":     { action: "reject",     reason: "Email rejected by DMARC policy" }
  };

  const outcome = actions[effectivePolicy] ?? { action: "quarantine", reason: "Unknown policy, defaulting to quarantine" };
  const riskScore = calculateRiskScore(false, effectivePolicy, pct, spf.status, dkim.status);

  return {
    status: "fail",
    policy, sp, effectivePolicy, pct, aspf, adkim,
    spfAligned, dkimAligned, riskScore,
    fromDomain,  // ← add this
    ...outcome
  };
};


const checkAlignment = (authStatus, authDomain, fromDomain, mode) => {
  // Must pass authentication first — alignment alone is not enough
  if (authStatus !== "pass") return false;

  // No domain to check against
  if (!authDomain || !fromDomain) return false;

  if (mode === "s") {
    // Strict — domains must match exactly
    // e.g. mail.legitbank.com does NOT align with legitbank.com
    return authDomain === fromDomain;
  } else {
    // Relaxed — organisational domain just needs to match
    // e.g. mail.legitbank.com DOES align with legitbank.com
    return authDomain === fromDomain || authDomain.endsWith("." + fromDomain);
  }
};


// Determines which policy to apply based on whether auth came from a subdomain
// If auth domain is a subdomain of from domain and sp= is defined, use sp=
// Otherwise use the main policy p=
const determineEffectivePolicy = (spfDomain, dkimDomain, fromDomain, mainPolicy, subdomainPolicy) => {
  const authDomain = spfDomain || dkimDomain;
  
  if (!authDomain || !fromDomain) return mainPolicy;
  
  // Check if authDomain is a subdomain (not exact match and ends with .fromDomain)
  const isSubdomain = authDomain !== fromDomain && authDomain.endsWith("." + fromDomain);
  
  // Use subdomain policy if applicable and defined
  if (isSubdomain && subdomainPolicy) {
    return subdomainPolicy;
  }
  
  return mainPolicy;
};


// Risk Score Engine: 0-100 scale where 0 = safe, 100 = highly suspicious
// Considers: DMARC pass/fail, policy strength, pct threshold, and auth status
const calculateRiskScore = (aligned, policy, pct, spfStatus, dkimStatus) => {
  // If DMARC passes via alignment — very safe
  if (aligned) {
    return 5;
  }

  // DMARC failed — risk depends on policy and auth method status
  const spfFailed = spfStatus !== "pass";
  const dkimFailed = dkimStatus !== "pass";
  const bothFailed = spfFailed && dkimFailed;

  // Base risk from policy strength
  let risk;
  if (policy === "reject") {
    // Email will be blocked — low risk
    risk = bothFailed ? 20 : 10;
  } else if (policy === "quarantine") {
    // Email goes to spam — medium risk (user may still see it)
    risk = bothFailed ? 60 : 40;
  } else {
    // policy === "none" → monitoring only, email delivers unprotected — high risk
    risk = bothFailed ? 85 : 70;
  }

  // Adjust for pct threshold — percentage of emails that receive the policy action
  // If pct < 100, some failing emails slip through without policy enforcement
  if (pct < 100) {
    const bypassRisk = ((100 - pct) / 100) * 25;
    risk += bypassRisk;
  }

  // Cap at 100
  return Math.min(Math.round(risk), 100);
};


module.exports = { evaluateDMARC, checkAlignment };