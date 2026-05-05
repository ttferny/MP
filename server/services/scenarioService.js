const scenarios = {
  "legitimate": {
    icon: "✅",
    name: "Legitimate Email",
    desc: "A real email from legitbank.com, sent from their authorised server with a valid DKIM signature.",
    attack: "No attack. This is the baseline — a genuine email that should always be delivered.",
    spf:          { status: "pass", domain: "legitbank.com" },
    dkim:         { status: "pass", domain: "legitbank.com" },
    fromDomain:   "legitbank.com",
    defaultPolicy: "reject",
    explanation:  "Both SPF and DKIM align with the From: domain. DMARC passes regardless of policy. Email is delivered normally."
  },

  "basic-spoof": {
    icon: "❌",
    name: "Basic Spoofed Sender",
    desc: "An attacker sends an email pretending to be legitbank.com but from their own server with no valid signature.",
    attack: "Attacker sets From: legitbank.com but sends from evil.com. SPF and DKIM both fail alignment.",
    spf:          { status: "fail", domain: "evil.com" },
    dkim:         { status: "fail", domain: "evil.com" },
    fromDomain:   "legitbank.com",
    defaultPolicy: "reject",
    explanation:  "Neither SPF nor DKIM align with the From: domain. DMARC catches this as a spoof. With p=reject the email is blocked entirely. Change the policy to none to see how a misconfigured domain would let this through."
  },

  "ceo-fraud": {
    icon: "🎭",
    name: "CEO Fraud",
    desc: "Attacker impersonates a company CEO to trick the finance team into transferring money.",
    attack: "Attacker registers ceo-company.com (looks similar), passes SPF on that domain, but the From: shows ceo@company.com. DKIM is missing.",
    spf:          { status: "pass", domain: "ceo-company.com" },
    dkim:         { status: "fail", domain: "" },
    fromDomain:   "company.com",
    defaultPolicy: "quarantine",
    explanation:  "SPF passes on a lookalike domain but it does not align with the From: domain company.com. DMARC catches the mismatch. With p=quarantine the email goes to spam instead of the inbox — the finance team may still see it, which is why p=reject is safer."
  },

  "banking-phish": {
    icon: "🏦",
    name: "Banking Phishing",
    desc: "Mass phishing campaign spoofing a bank to steal customer credentials via a fake login page.",
    attack: "Attacker fully spoofs dbs.com.sg — forges the From: header. No valid SPF or DKIM for the real domain.",
    spf:          { status: "fail", domain: "phish-server.com" },
    dkim:         { status: "fail", domain: "phish-server.com" },
    fromDomain:   "dbs.com.sg",
    defaultPolicy: "reject",
    explanation:  "Classic phishing attack. Both SPF and DKIM fail alignment. A strong p=reject policy blocks this immediately. Many banks now enforce p=reject specifically because of attacks like this."
  },

  "monitor-only": {
    icon: "👀",
    name: "Weak DMARC Policy",
    desc: "The domain has DMARC set up but only in monitoring mode — a common misconfiguration.",
    attack: "Same spoofed email as basic-spoof, but the domain owner set p=none meaning DMARC takes no action.",
    spf:          { status: "fail", domain: "evil.com" },
    dkim:         { status: "fail", domain: "evil.com" },
    fromDomain:   "example.com",
    defaultPolicy: "none",
    explanation:  "This is the most common real-world misconfiguration. DMARC detects the spoof but does nothing because the policy is none. The spoofed email is delivered to the inbox. This is why organisations must move from p=none to p=quarantine or p=reject."
  },

  "spf-misalign": {
    icon: "🔀",
    name: "SPF Pass, Misaligned",
    desc: "A subtle attack where SPF passes but on the wrong domain — exactly the gap DMARC was designed to close.",
    attack: "Attacker's server has a valid SPF record for evil.com. SPF passes. But the From: header shows legitbank.com. Without DMARC, this slips through.",
    spf:          { status: "pass", domain: "evil.com" },
    dkim:         { status: "fail", domain: "" },
    fromDomain:   "legitbank.com",
    defaultPolicy: "reject",
    explanation:  "This is the most important scenario. SPF says pass — but for evil.com, not legitbank.com. Without DMARC alignment checking, this email would be delivered. DMARC catches that SPF passed for the wrong domain and rejects it. This is why checking alignment, not just SPF status, is critical."
  },

  "strict-fail": {
  icon: "🔒",
  name: "Strict Alignment Fail",
  desc: "Email sent from a subdomain mail.legitbank.com but DMARC is set to strict alignment.",
  attack: "Not an attack — this shows how strict mode can break legitimate subdomain senders.",
  spf:          { status: "pass", domain: "mail.legitbank.com" },
  dkim:         { status: "pass", domain: "mail.legitbank.com" },
  fromDomain:   "legitbank.com",
  defaultPolicy: "reject",
  aspf:         "s",   // strict
  adkim:        "s",   // strict
  explanation:  "The subdomain mail.legitbank.com does not exactly match legitbank.com in strict mode. Even though SPF and DKIM both pass, alignment fails. This is why most domains use relaxed mode."
},

"relaxed-pass": {
  icon: "🔓",
  name: "Relaxed Alignment Pass",
  desc: "Same subdomain email but DMARC is set to relaxed alignment — the default.",
  attack: "Not an attack — shows how relaxed mode correctly allows legitimate subdomain senders.",
  spf:          { status: "pass", domain: "mail.legitbank.com" },
  dkim:         { status: "pass", domain: "mail.legitbank.com" },
  fromDomain:   "legitbank.com",
  defaultPolicy: "reject",
  aspf:         "r",   // relaxed
  adkim:        "r",   // relaxed
  explanation:  "In relaxed mode, mail.legitbank.com aligns with legitbank.com because they share the same organisational domain. SPF and DKIM both pass and align. Email is delivered. This is the default behaviour and the most common real-world configuration."
},

"forwarded-email": {
  icon: "📧",
  name: "Forwarded Email",
  desc: "A legitimate email forwarded by a third-party service like Gmail, which changes the From: header.",
  attack: "Not an attack — shows a common legitimate scenario that DMARC can break.",
  spf:          { status: "pass", domain: "mail.google.com" },
  dkim:         { status: "pass", domain: "mail.google.com" },
  fromDomain:   "example.com",
  defaultPolicy: "reject",
  explanation:  "When Gmail forwards an email, it passes SPF/DKIM for gmail.com but the From: shows the original domain example.com. Neither aligns. Without sp= (subdomain policy), strict p=reject would block this. With sp=quarantine, forwarded mail goes to spam—frustrating but safer than p=none."
},

"subdomain-spoof": {
  icon: "🚨",
  name: "Subdomain Spoof Attack",
  desc: "Attacker creates a lookalike subdomain to bypass organizational domain checks.",
  attack: "Attacker registers newsletter.company.com and gets SPF to pass. From: is set to alerts@company.com. Attacker hopes relaxed mode will see 'company.com' and pass.",
  spf:          { status: "pass", domain: "newsletter.company.com" },
  dkim:         { status: "fail", domain: "" },
  fromDomain:   "company.com",
  defaultPolicy: "reject",
  aspf:         "r",   // relaxed
  adkim:        "r",   // relaxed
  explanation:  "In relaxed mode, newsletter.company.com (SPF) aligns with company.com (From:). SPF passes and aligns. DMARC passes. The attacker registered a lookalike subdomain. This shows why organizations should monitor SPF records across all subdomains, not just the main domain."
},

"pct-50-pass": {
  icon: "50️⃣",
  name: "Partial Enforcement (Pass)",
  desc: "A legitimate email with p=quarantine pct=50. Only 50% of emails get the policy action.",
  attack: "Not an attack — shows a gradual rollout strategy, but creates security gaps.",
  spf:          { status: "pass", domain: "legitbank.com" },
  dkim:         { status: "pass", domain: "legitbank.com" },
  fromDomain:   "legitbank.com",
  defaultPolicy: "quarantine",
  explanation:  "With pct=50, only 50% of emails get quarantined. This email happened to pass DMARC anyway so pct doesn't matter. Risk is low."
},

"pct-50-fail": {
  icon: "⚠️",
  name: "Partial Enforcement (Fail)",
  desc: "Spoofed email with p=quarantine pct=50. Only 50% get quarantined, 50% slip through.",
  attack: "Attacker sends spoofed email. With pct=50, roughly half bypass quarantine and reach inboxes.",
  spf:          { status: "fail", domain: "evil.com" },
  dkim:         { status: "fail", domain: "evil.com" },
  fromDomain:   "company.com",
  defaultPolicy: "quarantine",
  explanation:  "This is why pct < 100 is risky. DMARC would block this email 50% of the time, but the other 50% slip through to inboxes. Attackers can retry until they hit the pct window. Organizations should use pct=100 for maximum protection."
},

"subdomain-policy": {
  icon: "🔗",
  name: "Subdomain Policy (sp=)",
  desc: "Email from subdomain with sp=none (subdomain policy), main domain has p=reject.",
  attack: "Not an attack — shows how sp= allows subdomains to have different policies.",
  spf:          { status: "fail", domain: "evil.com" },
  dkim:         { status: "fail", domain: "evil.com" },
  fromDomain:   "mail.legitbank.com",
  defaultPolicy: "reject",
  sp:           "none",
  explanation:  "The main domain legitimbank.com has p=reject, but mail.legitbank.com has sp=none (monitoring only). This email fails DMARC on the subdomain, so sp=none applies instead of the main p=reject. Email is delivered for monitoring."
},

};

// Return all scenario keys and names (for listing)
const getAllScenarios = () => {
  return Object.entries(scenarios).map(([key, s]) => ({
    key,
    name: s.name,
    icon: s.icon,
    defaultPolicy: s.defaultPolicy
  }));
};

// Return a single scenario by key
const getScenario = (key) => scenarios[key] || null;

module.exports = { getAllScenarios, getScenario };
