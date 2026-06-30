// Zircon

const evaluateDMARC = (spf, dkim, parsed) => {

  if (!spf || !dkim) {
    return { status: "error", action: "none", reason: "Missing SPF or DKIM result" };
  }

  const policy = parsed?.policy || null;
  const fromDomain = parsed?.fromDomain || null;
  const pct = parsed?.pct ?? 100;
  const aspf = parsed?.aspf || "r";
  const adkim = parsed?.adkim || "r";
  const sp = parsed?.sp || null;

  if (!policy) {
    return {
      status: "error",
      action: "none",
      verdict: "none",
      policy: null,
      sp,
      pct,
      aspf,
      adkim,
      spfAligned: false,
      dkimAligned: false,
      reason: "No DMARC record found",
      fromDomain,
    };
  }

  const spfCheck  = checkAlignment(spf.status,  spf.domain,  fromDomain, aspf);
  const dkimCheck = checkAlignment(dkim.status, dkim.domain, fromDomain, adkim);

  const spfAligned  = spfCheck.aligned;
  const dkimAligned = dkimCheck.aligned;

  if (spfAligned || dkimAligned) {
    const riskScore = calculateRiskScore(true, policy, pct, spf.status, dkim.status);
    return {
      status: "pass",
      action: "deliver",
      verdict: "deliver",
      reason: `DMARC passed via ${spfAligned ? "SPF" : "DKIM"} alignment (${spfAligned ? aspf : adkim} mode)`,
      policy,
      pct,
      aspf,
      adkim,
      sp,
      spfAligned,
      dkimAligned,
      alignmentDetails: {
        spf:  spfCheck.reason,
        dkim: dkimCheck.reason,
      },
      riskScore,
      fromDomain,
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
    action: outcome.action,
    verdict: outcome.action,
    reason: outcome.reason,
    policy,
    sp,
    effectivePolicy,
    pct,
    aspf,
    adkim,
    spfAligned,
    dkimAligned,
    alignmentDetails: {
      spf:  spfCheck.reason,
      dkim: dkimCheck.reason,
    },
    riskScore,
    fromDomain,
  };
};


const checkAlignment = (authStatus, authDomain, fromDomain, mode) => {
  if (authStatus !== "pass") {
    return { aligned: false, reason: `Auth status was "${authStatus}", not "pass" — cannot align a failed check` };
  }
  if (!authDomain || !fromDomain) {
    return { aligned: false, reason: "Missing domain — cannot compare alignment" };
  }

  if (mode === "s") {
    const aligned = authDomain === fromDomain;
    return {
      aligned,
      reason: aligned
        ? `Strict mode: ${authDomain} exactly matches From domain ${fromDomain}`
        : `Strict mode: ${authDomain} does not exactly match From domain ${fromDomain} — strict alignment requires an exact match`
    };
  } else {
    const authOrg = getOrgDomain(authDomain);
    const fromOrg = getOrgDomain(fromDomain);
    const aligned = authOrg === fromOrg;
    return {
      aligned,
      reason: aligned
        ? `Relaxed mode: ${authDomain} and ${fromDomain} share organisational domain ${fromOrg}`
        : `Relaxed mode: ${authDomain} (org: ${authOrg}) does not share an organisational domain with ${fromDomain} (org: ${fromOrg})`
    };
  }
};

// Extracts the organisational domain from a full domain name
// e.g. mail.tp.edu.sg → tp.edu.sg
// e.g. smtp.google.com → google.com
// e.g. legitbank.com → legitbank.com
const getOrgDomain = (domain) => {
  if (!domain) return "";

  const parts = domain.split(".");

  // Known two-part TLDs like .edu.sg, .com.sg, .gov.sg, .ac.uk
  const twoPartTLDs = ["edu.sg", "com.sg", "gov.sg", "net.sg", "ac.uk", "co.uk", "org.uk", "com.au", "edu.au"];
  const last2 = parts.slice(-2).join(".");

  if (twoPartTLDs.includes(last2) && parts.length >= 3) {
    // e.g. mail.tp.edu.sg → take last 3 parts → tp.edu.sg
    return parts.slice(-3).join(".");
  }

  // Standard domain — take last 2 parts
  // e.g. mail.google.com → google.com
  // e.g. smtp.legitbank.com → legitbank.com
  return parts.slice(-2).join(".");
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