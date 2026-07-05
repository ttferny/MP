# SPF Features — Email Authentication Studio

This document collates every **SPF (Sender Policy Framework)** feature in the **Email Authentication Studio** project (`email-auth-simulator`), the files that implement them, how to use each one, and how SPF connects to the wider email authentication stack (DKIM and DMARC).

---

## What SPF Does

SPF answers one question at the SMTP layer:

> **Is the IP address that delivered this message authorised to send mail for the envelope domain (Return-Path / MAIL FROM)?**

A domain publishes an SPF policy as a DNS **TXT** record starting with `v=spf1`. Receiving servers look up that record and walk its mechanisms (`ip4`, `include`, `mx`, `a`, `redirect`, `all`) until the sender IP matches or the policy ends.

| SPF result | Meaning |
|------------|---------|
| `pass` | Sender IP is authorised |
| `fail` | Sender IP is not authorised (hard fail, `-all`) |
| `softfail` | Sender IP is suspicious (`~all`) |
| `neutral` | Domain makes no strong claim (`?all`) |
| `none` | No SPF record found |
| `permerror` | Malformed or conflicting SPF record |
| `temperror` | Temporary DNS failure |

SPF alone does **not** prove the visible `From:` address is genuine. **DMARC** closes that gap by requiring SPF (or DKIM) to **pass and align** with the `From:` domain. See [Linking SPF to Email Authentication](#linking-spf-to-email-authentication) below.

---

## Quick Start

```bash
cd MP
npm install
npm start
```

Server: `http://localhost:3000`

| Page | URL |
|------|-----|
| Header Parser (full SPF + DKIM + DMARC pipeline) | `/` or `index.html` |
| Live SPF Auditor | `spf.html` |
| SPF Record Builder | `spf-builder.html` |
| SPF Learning Simulator | `spf-simulator.html` |
| DMARC Lab (uses SPF in scenarios) | `dmarc.html` |
| DNS Studio (SPF record discovery) | `dns-studio.html` |

Run SPF tests:

```bash
npm test -- server/test/spf.test.js
```

---

## Architecture Overview

```
Raw email header
      │
      ▼
 parser.js          ← extracts envelopeDomain, senderIP, fromDomain
      │
      ▼
 spf.js             ← DNS lookup + mechanism evaluation
      │
      ├──► /api/spf/*     (standalone auditor, builder handoff, simulator)
      │
      ▼
 dkim.js  +  dmarc.js   ← DMARC uses SPF pass + domain alignment
      │
      ▼
 aiChecker.js (optional) ← AI reads SPF/DKIM/DMARC context
```

---

## File Inventory

### Backend — Core Engine

| File | Purpose |
|------|---------|
| [`server/services/spf.js`](server/services/spf.js) | RFC 7208 SPF evaluator. Parses records, evaluates mechanisms, tracks DNS lookup count (10-lookup limit), builds evaluation trace. |
| [`server/services/dns.js`](server/services/dns.js) | `lookupSPFRecord(domain)` — fetches `v=spf1` TXT records from public DNS. |
| [`server/services/parser.js`](server/services/parser.js) | Extracts `envelopeDomain` (Return-Path) and `senderIP` (from `Received`, `Received-SPF`, or `Authentication-Results`) for SPF checks. |
| [`server/utils/validate.js`](server/utils/validate.js) | `validateSPFResult()`, `isValidIP()`, `isValidDomain()` — input/output guards for SPF APIs. |
| [`server/routes/spfRoutes.js`](server/routes/spfRoutes.js) | REST routes: live check, policy simulation, commercial risk summary. |
| [`server/routes/analyse.js`](server/routes/analyse.js) | Main pipeline: parse → SPF → DKIM → DMARC → optional AI. |
| [`server/services/autoDnsChecker.js`](server/services/autoDnsChecker.js) | Batch DNS check; reports whether a domain publishes SPF. |
| [`server/routes/dnsRoutes.js`](server/routes/dnsRoutes.js) | `/api/dns/check`, `/full-check` — includes SPF presence in results. |

**Key exports from `spf.js`:**

```javascript
const {
  checkSPF,              // used by /api/analyse/header
  parseSPFRecord,        // tokenise a v=spf1 string
  evaluateSPFRecord,       // full record walk (testable with mock DNS)
  evaluateSPFInteractive, // live auditor + /api/spf/check
  SPF_RESULTS,           // pass, fail, softfail, neutral, none, permerror, temperror
} = require('./server/services/spf');
```

**Supported mechanisms:** `ip4`, `ip6` (basic), `a`, `mx`, `include`, `redirect`, `all`

### Backend — Email Authentication Integration

| File | SPF role |
|------|----------|
| [`server/services/dmarc.js`](server/services/dmarc.js) | `evaluateDMARC(spf, dkim, parsed)` — checks SPF **pass + alignment** with `From:` domain. |
| [`server/services/scenarioService.js`](server/services/scenarioService.js) | 13 attack/auth lab scenarios; many demonstrate SPF pass/fail and misalignment. |
| [`server/routes/dmarcRoutes.js`](server/routes/dmarcRoutes.js) | DMARC lab API; scenarios pass `{ status, domain }` SPF objects. |
| [`server/services/smtpReceiver.js`](server/services/smtpReceiver.js) | Local SMTP demo (port 2525); uses envelope vs From match as a simplified SPF proxy for live DMARC demos. |
| [`server/services/aiChecker.js`](server/services/aiChecker.js) | Sends SPF/DKIM/DMARC results to Gemini for phishing classification. |
| [`server/services/dmarcReportAnalyzer.js`](server/services/dmarcReportAnalyzer.js) | Parses aggregate reports; surfaces SPF pass/fail statistics per domain. |

### Frontend — SPF UI

| File | Purpose |
|------|---------|
| [`client/spf.html`](client/spf.html) + [`client/spf.js`](client/spf.js) + [`client/spf.css`](client/spf.css) | **Live SPF Auditor** — domain + IP input, DNS A/MX display, mechanism trace timeline, 10-lookup speedometer, commercial risk panel. |
| [`client/spf-builder.html`](client/spf-builder.html) + [`client/spf-builder.js`](client/spf-builder.js) + [`client/spf-builder.css`](client/spf-builder.css) | **SPF Record Builder** — compose `v=spf1` from known ESP includes (Google, M365, SendGrid, etc.), custom IPs, and policy qualifier. |
| [`client/spf-simulator.html`](client/spf-simulator.html) + [`client/spf-simulator.js`](client/spf-simulator.js) + [`client/spf-simulator.css`](client/spf-simulator.css) | **Educational Simulator** — client-side scenarios (pass, fail, include, missing record, duplicate records, forwarding, softfail, hardfail). |
| [`client/index.html`](client/index.html) + [`client/script.js`](client/script.js) | **Header Parser** — runs full auth pipeline; built-in `spf-pass` and `spf-fail` test cases. |
| [`client/dns-studio.html`](client/dns-studio.html) | Shows SPF record presence alongside DMARC and DKIM selectors. |

### Tests & Utilities

| File | Purpose |
|------|---------|
| [`server/test/spf.test.js`](server/test/spf.test.js) | Unit tests for `parseSPFRecord`, parser helpers, validation, spoof header detection. |
| [`server/test/api.test.js`](server/test/api.test.js) | Integration tests for `/api/analyse/header` (mocks DNS/DKIM/DMARC). |
| [`server/test/testIntegration.js`](server/test/testIntegration.js) | Runs all 13 DMARC scenarios (server must be running). |
| [`tmp-spf-sim-test.js`](tmp-spf-sim-test.js) | Smoke script for `/api/spf/simulate` scenario keys. |

### Related Documentation

| File | Contents |
|------|----------|
| [`QUICK_START.md`](QUICK_START.md) | DNS Studio quick start and API examples |
| [`DNS_AUTOMATION_GUIDE.md`](DNS_AUTOMATION_GUIDE.md) | Automated SPF/DMARC/DKIM DNS checks |
| [`DMARC_ANALYZER_README.md`](DMARC_ANALYZER_README.md) | DMARC aggregate report analyzer (includes SPF stats) |

---

## Feature Guide

### 1. Live SPF Auditor (`spf.html`)

**What it is for:** Check whether a specific sending IP is authorised for a domain using live public DNS. Shows the full evaluation trace and DNS lookup budget (RFC limit: 10 lookups).

**How to use (UI):**

1. Open `http://localhost:3000/spf.html`
2. Enter a domain (e.g. `google.com`) and sender IP (e.g. `142.250.185.73`)
3. Click **Check SPF**
4. Review: SPF record, result badge, mechanism trace, include chain, commercial risk summary

**Deep link from builder:**

```
http://localhost:3000/spf.html?domain=example.com
```

**API example:**

```bash
curl -X POST http://localhost:3000/api/spf/check \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com", "ip": "142.250.185.73"}'
```

**Sample response (abbreviated):**

```json
{
  "success": true,
  "domain": "google.com",
  "ip": "142.250.185.73",
  "record": "v=spf1 include:_spf.google.com ~all",
  "result": "pass",
  "reason": "Sender IP matched mechanism ip4:...",
  "lookupCount": 2,
  "trace": [
    { "mechanism": "include:_spf.google.com", "outcome": "pass", "detail": "..." }
  ],
  "commercial": {
    "status": "Authorized",
    "riskScore": 10,
    "recommendation": "Maintain current SPF policy and monitor for drift."
  }
}
```

`POST /api/spf/evaluate` is an alias for `/check`.

---

### 2. SPF Record Builder (`spf-builder.html`)

**What it is for:** Compose a valid SPF TXT record without memorising include strings. Tracks estimated DNS lookup count and warns when approaching the 10-lookup limit.

**How to use (UI):**

1. Open `http://localhost:3000/spf-builder.html`
2. Select email services (Google Workspace, Microsoft 365, SendGrid, Mailchimp, etc.)
3. Add custom `ip4:` addresses if needed
4. Choose a terminal policy: `-all` (recommended), `~all`, or `?all`
5. Copy the generated record, or click **Test in Auditor** to open `spf.html` with your domain

**Example output:**

```
v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.10 -all
```

**Programmatic pattern (from `spf-builder.js`):**

```javascript
// After building a record, hand off to the auditor:
window.location.href = `spf.html?domain=${encodeURIComponent(domain)}`;
```

---

### 3. SPF Policy Simulator (`spf-simulator.html` + `/api/spf/simulate`)

**What it is for:** Learn how `~all` (softfail) vs `-all` (hardfail) changes delivery behaviour when an unauthorised sender tries to spoof a domain.

**Client-side scenarios** (`spf-simulator.js`):

| Scenario | Teaches |
|----------|---------|
| Authorised sender | Clean SPF pass |
| Unknown server | SPF fail |
| CEO fraud | Convincing spoof from wrong IP |
| Include chain | Legitimate ESP via `include:` |
| Missing SPF | `none` result — no protection |
| Duplicate records | `permerror` — invalid config |
| Forwarding | SPF breakage after mail forwarding |
| Softfail / Hardfail | `~all` vs `-all` delivery difference |

**Server-side scenarios** (`spfRoutes.js` — used by `/api/spf/simulate`):

| Key | Domain | Description |
|-----|--------|-------------|
| `ceo-fraud` | `company.com` | Spoofed executive from unauthorised IP |
| `phishing` | `dbs.com` | Fake bank alert from attacker IP |
| `legit-newsletter` | `news.example.com` | Legitimate ESP sender |
| `misconfigured` | `vulnerable.org` | Weak `?all` policy |

**API example:**

```bash
curl -X POST http://localhost:3000/api/spf/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "company.com",
    "attackerIP": "198.51.100.99",
    "scenarioKey": "ceo-fraud"
  }'
```

**Node smoke test:**

```bash
node tmp-spf-sim-test.js
```

Returns side-by-side outcomes for soft (`~all`) and hard (`-all`) policies, including simulated SMTP responses (`250 Ok` vs `550 5.7.1`).

---

### 4. Header Parser — Full Auth Pipeline (`index.html`)

**What it is for:** Paste a real email header and run SPF, DKIM, and DMARC together — the primary end-to-end email authentication workflow.

**How SPF fits in:**

1. `parser.js` reads `Return-Path` → `envelopeDomain`
2. `Address `Received` / `Received-SPF` / `Authentication-Results` → `senderIP`
3. `spf.js` `checkSPF(parsed)` evaluates the envelope domain against that IP
4. Result flows to `dmarc.js` for alignment with the visible `From:` domain

**API example:**

```bash
curl -X POST http://localhost:3000/api/analyse/header \
  -H "Content-Type: application/json" \
  -d '{
    "rawHeader": "From: payroll@paypal.com\nReturn-Path: <payroll@paypal.com>\nReceived: from sender-unsafe.example.net (sender-unsafe.example.net [203.0.113.88])\nSubject: Updated payroll details",
    "content": "Please verify your account..."
  }'
```

**Built-in test cases in the UI:**

| Key | Label | SPF lesson |
|-----|-------|------------|
| `spf-pass` | Authorized Sender | Real Spotify header — live DNS determines result |
| `spf-fail` | Spoofed Sender | PayPal `From:` from `203.0.113.88` — should fail SPF for paypal.com |

**Programmatic usage (server-side):**

```javascript
const { parseEmailHeader } = require('./server/services/parser');
const { checkSPF } = require('./server/services/spf');

const parsed = parseEmailHeader(rawHeader);
const spfResult = await checkSPF(parsed);
// → { result, reason, record, matchedMechanism, domain, ip }
```

---

### 5. DNS Studio — SPF Discovery (`dns-studio.html`)

**What it is for:** Quickly see whether a domain publishes SPF (alongside DMARC and DKIM selectors) without evaluating a specific IP.

**API example:**

```bash
curl -X POST http://localhost:3000/api/dns/check \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

See [`DNS_AUTOMATION_GUIDE.md`](DNS_AUTOMATION_GUIDE.md) for full endpoint documentation.

---

### 6. DMARC Lab Scenarios (SPF in context)

**What it is for:** Demonstrate why SPF alone is insufficient — especially when SPF passes on the **wrong** domain.

**Key scenarios in [`server/services/scenarioService.js`](server/services/scenarioService.js):**

| Scenario | SPF | DMARC lesson |
|----------|-----|--------------|
| `spf-misalign` | pass on `evil.com` | SPF passes but does not align with `From: legitbank.com` — DMARC rejects |
| `ceo-fraud` | pass on lookalike domain | SPF passes on `ceo-company.com`, `From:` shows `company.com` |
| `relaxed-pass` | pass on `mail.legitbank.com` | Relaxed alignment (`aspf=r`) allows subdomain match |
| `strict-fail` | pass on subdomain | Strict alignment (`aspf=s`) rejects subdomain mismatch |

**API example:**

```bash
curl http://localhost:3000/api/dmarc/scenarios/spf-misalign
```

---

## Linking SPF to Email Authentication

### The three layers

```
┌─────────────────────────────────────────────────────────────┐
│  SPF   — Is this sending IP authorised for envelope domain? │
│  DKIM  — Is the message cryptographically signed?           │
│  DMARC — Does SPF or DKIM pass AND align with From: domain? │
└─────────────────────────────────────────────────────────────┘
```

SPF checks the **envelope** (Return-Path / MAIL FROM), not the visible `From:` header. An attacker can pass SPF on their own domain while forging `From: yourbank.com`. DMARC requires:

1. SPF **or** DKIM authentication passes, **and**
2. The authenticated domain **aligns** with the `From:` domain (`aspf=r` relaxed or `aspf=s` strict)

DMARC passes if **either** SPF or DKIM aligns.

### Data flow between modules

```javascript
// parser.js output (relevant SPF fields)
{
  envelopeDomain: "bounces@em.spotify.com",  // from Return-Path
  senderIP:       "159.183.83.220",          // from Received / Received-SPF
  fromDomain:     "spotify.com"              // from From: header (used by DMARC)
}

// spf.js output (from checkSPF)
{
  result: "pass",           // note: field is "result"
  reason: "...",
  record: "v=spf1 ...",
  domain: "em.spotify.com",
  ip:     "159.183.83.220"
}

// Shape expected by dmarc.js evaluateDMARC()
{
  status: "pass",           // note: field is "status"
  domain: "em.spotify.com"
}
```

When calling `evaluateDMARC()` directly (e.g. DMARC Lab `/api/dmarc/evaluate`), normalise SPF output:

```javascript
const spfForDmarc = {
  status: spfResult.result,
  domain: spfResult.domain,
};
const dmarcResult = evaluateDMARC(spfForDmarc, dkimResult, dmarcParsed);
```

The main header parser UI handles both field names via `getResultValue()` in `client/script.js`.

### Why alignment matters — worked example

**Attack:** Attacker sends from IP `198.51.100.10` with:
- `From: ceo@company.com`
- `Return-Path: attacker@evil.com` (attacker owns `evil.com` and publishes SPF for it)

| Check | Result | Detail |
|-------|--------|--------|
| SPF | **pass** | IP authorised for `evil.com` |
| SPF alignment | **fail** | `evil.com` ≠ `company.com` |
| DMARC (`p=reject`) | **fail** | Neither SPF nor DKIM aligned → reject |

This is the `spf-misalign` scenario. **SPF status alone would misleadingly look safe.**

### AI layer

When `GEMINI_API_KEY` is set in `.env`, `aiChecker.js` receives the full SPF/DKIM/DMARC context after protocol checks:

```
POST /api/analyse/header  →  { results: { spf, dkim, dmarc }, ai: { classification, ... } }
```

SPF results inform the AI assessment but do not replace protocol verification.

---

## API Reference — SPF Endpoints

All routes are mounted at `/api/spf` in [`server/app.js`](server/app.js).

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/api/spf/check` | `{ domain, ip }` | Live SPF evaluation + DNS context + commercial summary |
| POST | `/api/spf/evaluate` | `{ domain, ip }` | Alias for `/check` |
| POST | `/api/spf/simulate` | `{ domain, attackerIP, scenarioKey? }` | Soft vs hard policy simulation |

### Related auth endpoints that use SPF

| Method | Path | SPF role |
|--------|------|----------|
| POST | `/api/analyse/header` | Full pipeline including `checkSPF()` |
| POST | `/api/analyse/domain` | Returns published SPF TXT record for a domain |
| POST | `/api/dns/check` | Reports SPF presence |
| POST | `/api/dns/full-check` | SPF + DMARC + DKIM batch check |
| GET | `/api/dmarc/scenarios/:key` | Returns preset SPF/DKIM statuses for lab scenarios |
| POST | `/api/dmarc/evaluate` | Accepts `{ spf: { status, domain }, dkim, parsed }` |

---

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | HTTP server |
| `SMTP_PORT` | `2525` | Local SMTP receiver for DMARC live demos |
| `GEMINI_API_KEY` | — | Optional AI phishing analysis |

There are **no SPF-specific environment variables**. SPF evaluation uses live public DNS via Node's `dns.promises` module.

---

## Testing

```bash
# All tests
npm test

# SPF unit tests only
npm test -- server/test/spf.test.js

# Manual DMARC scenario runner (server must be running)
node server/test/testIntegration.js

# SPF simulate smoke test (server must be running)
node tmp-spf-sim-test.js
```

**What `spf.test.js` covers:**

- `parseSPFRecord()` — valid/invalid tokenisation
- `parser.js` — header extraction for SPF inputs
- `validateSPFResult()` — output shape validation
- Spoof detection patterns in sample headers

---

## Typical Workflows

### Publish a new SPF record

1. **Build** the record in `spf-builder.html`
2. **Publish** the TXT record in your DNS provider
3. **Verify** with `spf.html` (enter domain + your mail server IP)
4. **Confirm alignment** by sending a test message and pasting headers into `index.html`
5. **Monitor** via DMARC aggregate reports in `dmarc_analyzer.html`

### Investigate a spoofing attempt

1. Paste the suspicious header into `index.html`
2. Check SPF result — did the sending IP match the envelope domain?
3. Check DMARC — did SPF/DKIM align with the visible `From:`?
4. Run `spf.html` with the attacker's IP and the claimed domain to see the raw SPF verdict
5. Try the `spf-misalign` scenario in DMARC Lab to understand the attack pattern

### Learn SPF mechanisms

1. Start at `spf-simulator.html` for visual walkthroughs
2. Use `/api/spf/simulate` with `ceo-fraud` and `phishing` scenarios
3. Read the evaluation trace in `spf.html` for a real domain

---

## Summary

| Feature | Primary files | Entry point |
|---------|---------------|-------------|
| SPF engine | `server/services/spf.js`, `server/services/dns.js` | `checkSPF()`, `evaluateSPFInteractive()` |
| Live auditor | `client/spf.html`, `server/routes/spfRoutes.js` | `POST /api/spf/check` |
| Record builder | `client/spf-builder.html` | UI only |
| Policy simulator | `client/spf-simulator.html`, `spfRoutes.js` | `POST /api/spf/simulate` |
| Full auth pipeline | `client/index.html`, `server/routes/analyse.js` | `POST /api/analyse/header` |
| DMARC integration | `server/services/dmarc.js`, `scenarioService.js` | DMARC Lab scenarios |
| DNS discovery | `client/dns-studio.html`, `autoDnsChecker.js` | `POST /api/dns/check` |

SPF is the first authentication check in the pipeline. DMARC builds on it by enforcing domain alignment — together they form the practical defence against email spoofing and phishing that this project demonstrates end to end.
