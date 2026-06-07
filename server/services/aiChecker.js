/**
 * ============================================================
 * aiChecker.js — AI-Powered Phishing & Spoofing Content Checker
 * ============================================================
 *
 * WHAT THIS DOES:
 * ---------------
 * Sends the email's subject, sender, and header signals to
 * Gemini (Google AI API) which analyses the content and returns:
 *   - A threat classification (safe / suspicious / phishing / spoofing)
 *   - A confidence score (0–100)
 *   - A list of red flags detected
 *   - A plain-English explanation for the user
 *
 * HOW IT LINKS:
 * -------------
 *   routes/analyse.js calls checkEmailWithAI(parsed, spfResult, dkimResult, dmarcResult)
 *   after the full SPF/DKIM/DMARC pipeline completes.
 *   The AI result is added to the final response sent to the frontend.
 */

const logger = require('../utils/logger');

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models';
const MODEL          = 'gemini-2.5-flash';

// ─────────────────────────────────────────────
// Sanitise a value before inserting into the prompt.
// Removes control characters, null bytes, and trims
// to a safe length so the payload is always valid JSON.
// ─────────────────────────────────────────────
function sanitise(val, maxLen = 300) {
  if (!val) return '(none)';
  return String(val)
    .replace(/\0/g, '')                    // null bytes
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars except \t \n
    .replace(/\\/g, '\\\\')               // escape backslashes
    .replace(/"/g, '\\"')                 // escape double quotes
    .slice(0, maxLen)
    .trim() || '(none)';
}

function buildPrompt(parsed, spfResult, dkimResult, dmarcResult, content = '') {
  const domainMismatch = parsed.fromDomain !== parsed.envelopeDomain;

  return `You are an email security analyst specialising in phishing and spoofing detection.

Analyse the following email header data and authentication results, then classify the email.

=== EMAIL HEADER DATA ===
From (visible):      ${sanitise(parsed.from)}
From Email:          ${sanitise(parsed.fromEmail)}
From Domain:         ${sanitise(parsed.fromDomain)}
Envelope Domain:     ${sanitise(parsed.envelopeDomain)}
Sender IP:           ${sanitise(parsed.senderIP)}
Subject:             ${sanitise(parsed.subject)}
Date:                ${sanitise(parsed.date)}
Reply-To:            ${sanitise(parsed.replyTo)}
Domain mismatch:     ${domainMismatch ? 'YES — From domain differs from envelope domain' : 'No'}
DKIM Selector:       ${sanitise(parsed.dkimSignature?.s)}
DKIM Signing Domain: ${sanitise(parsed.dkimSignature?.d)}

=== EMAIL CONTENT ===
${sanitise(content, 1000)}

=== AUTHENTICATION RESULTS ===
SPF:   ${sanitise(spfResult?.result)} — ${sanitise(spfResult?.reason)}
DKIM:  ${sanitise(dkimResult?.result)} — ${sanitise(dkimResult?.reason)}
DMARC: ${sanitise(dmarcResult?.verdict)} (policy: ${sanitise(dmarcResult?.policy)}) — ${sanitise(dmarcResult?.reason)}
SPF aligned:  ${dmarcResult?.spfAligned  ? 'yes' : 'no'}
DKIM aligned: ${dmarcResult?.dkimAligned ? 'yes' : 'no'}

=== YOUR TASK ===
Respond ONLY with a valid JSON object. No markdown. No code fences. No trailing commas. Single line.
Keep ALL string values under 100 characters. Keep redFlags array to max 5 items, each under 60 characters.

Analyse BOTH the authentication results AND the email content/subject for these signals:
- Urgency or fear tactics ("your account will be closed", "act now")
- Impersonation of known brands
- Suspicious links or requests for credentials
- Generic greetings vs personalised
- Mismatch between subject and content
- Unusual sender patterns or display name tricks

{"classification":"safe"|"suspicious"|"phishing"|"spoofing","confidence":<0-100>,"redFlags":["flag1","flag2"],"explanation":"plain English for non-technical user, focus on what the email says and why it is or is not safe","technicalSummary":"technical details covering both protocol results and content signals","recommendation":"open"|"review"|"delete"|"report"}

Classification: safe=all pass no suspicious content, suspicious=minor issues, phishing=fake sender or manipulative content, spoofing=forged domain
Confidence: 90-100 very certain, 70-89 likely, 50-69 possible, 0-49 uncertain`;
}

// ─────────────────────────────────────────────
// MAIN EXPORT: checkEmailWithAI
// ─────────────────────────────────────────────
async function checkEmailWithAI(parsed, spfResult, dkimResult, dmarcResult, content = '') {
  logger.info(`AI checker: analysing email from ${parsed.fromDomain}`);

  // Check API key exists before attempting the call
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    logger.error('AI checker: GEMINI_API_KEY is not set in environment');
    return fallbackResult('GEMINI_API_KEY is missing — add it to your .env file');
  }

  const prompt = buildPrompt(parsed, spfResult, dkimResult, dmarcResult, content);

  try {
    const response = await fetch(`${GEMINI_API_URL}/${MODEL}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          { role: 'user', parts: [{ text: prompt }] }
        ],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 2048,
          responseMimeType: 'application/json',
        },
      }),
    });

    if (!response.ok) {
      const err = await response.text();

      // Handle known temporary errors gracefully
      if (response.status === 503) {
        logger.warn('AI checker: Gemini API overloaded (503) — try again in a moment');
        return fallbackResult('AI service is temporarily busy. Please try again in a few seconds.');
      }
      if (response.status === 429) {
        logger.warn('AI checker: Gemini API rate limited (429)');
        return fallbackResult('Rate limit reached — please wait 60 seconds before analysing another email.');
      }
      if (response.status === 401 || response.status === 403) {
        logger.error(`AI checker: Authentication error ${response.status}`);
        return fallbackResult('Invalid or missing GEMINI_API_KEY. Check your .env file.');
      }

      logger.error(`AI checker: API error ${response.status} — ${err}`);
      return fallbackResult(`API error ${response.status} — AI analysis unavailable`);
    }

    let data;
    try {
      data = await response.json();
    } catch (jsonErr) {
      logger.error(`AI checker: Invalid JSON response — ${jsonErr.message}`);
      return fallbackResult('API returned invalid JSON — AI analysis unavailable');
    }

    // Extract text from Gemini response structure
    const raw = data.candidates
      ?.flatMap(c => c.content?.parts || [])
      .map(p => p.text || '')
      .join('') || '';

    // Debug log — shows exactly what Gemini returned
    logger.info(`AI checker: raw response = ${raw}`);

    // Parse the JSON response — clean up before parsing
    const cleaned = raw
      .replace(/```json|```/g, '')      // remove markdown fences
      .replace(/[\r\n]+/g, ' ')         // flatten newlines
      .replace(/[\u2018\u2019]/g, "'")  // curly single quotes → straight
      .replace(/[\u201C\u201D]/g, '"')  // curly double quotes → straight
      .trim();
    const jsonBlockMatch = cleaned.match(/\{[\s\S]*\}/);
    const jsonText = jsonBlockMatch ? jsonBlockMatch[0] : cleaned;

    let result;
    try {
      result = JSON.parse(jsonText);
    } catch {
      // JSON is truncated — extract what we can from the partial response
      result = extractLooseResult(raw);
    }

    logger.info(`AI checker: classification=${result.classification}, confidence=${result.confidence}`);
    return { success: true, ...result };

  } catch (err) {
    logger.error(`AI checker: failed — ${err.message}`);
    return fallbackResult(`AI analysis failed: ${err.message}`);
  }
}

// Returns a safe fallback when the API call fails
function fallbackResult(reason) {
  return {
    success:          false,
    classification:   'unknown',
    confidence:       0,
    redFlags:         [],
    explanation:      'AI analysis could not be completed. Please check authentication results manually.',
    technicalSummary: reason,
    recommendation:   'review',
  };
}

// Last-resort extraction when JSON parsing completely fails
function extractLooseResult(text) {
  // Pull individual fields using regex — works even on truncated JSON
  const pick = (re, fallback = '') => {
    const m = text.match(re);
    return m ? m[1].trim() : fallback;
  };

  const classification = pick(/"classification"\s*:\s*"([^"]+)"/i, 'suspicious').toLowerCase();
  const confidence     = Math.max(0, Math.min(100, parseInt(pick(/"confidence"\s*:\s*(\d+)/i, '50'), 10)));
  const recommendation = (() => {
    const r = pick(/"recommendation"\s*:\s*"([^"]+)"/i, '').toLowerCase();
    if (r) return r;
    // Fallback based on classification if recommendation was cut off
    if (classification === 'safe')       return 'open';
    if (classification === 'phishing')   return 'report';
    if (classification === 'spoofing')   return 'delete';
    return 'review';
  })();

  // Extract explanation — may be truncated, take whatever is there
  const explanation = pick(
    /"explanation"\s*:\s*"([^"]{10,})"/i,
    pick(/"explanation"\s*:\s*"([^"]+)/i, 'Email shows suspicious signals based on authentication results.')
  );

  const technicalSummary = pick(
    /"technicalSummary"\s*:\s*"([^"]{10,})"/i,
    pick(/"technicalSummary"\s*:\s*"([^"]+)/i, 'See SPF, DKIM and DMARC results for details.')
  );

  // Extract redFlags array items
  const redFlagsBlock = pick(/"redFlags"\s*:\s*\[([\s\S]*?)(?:\]|$)/i, '');
  const redFlags = redFlagsBlock
    ? [...redFlagsBlock.matchAll(/"([^"]+)"/g)].map(m => m[1]).filter(Boolean)
    : [];

  logger.info(`AI checker: extracted from partial response — classification=${classification}, confidence=${confidence}`);

  return { classification, confidence, redFlags, explanation, technicalSummary, recommendation };
}

module.exports = { checkEmailWithAI };