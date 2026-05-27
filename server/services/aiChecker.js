/**
 * ============================================================
 * aiChecker.js — AI-Powered Phishing & Spoofing Content Checker
 * ============================================================
 *
 * WHAT THIS DOES:
 * ---------------
 * Sends the email's subject, sender, and header signals to
 * Claude (Anthropic API) which analyses the content and returns:
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
const MODEL           = 'gemini-2.5-flash';

// ─────────────────────────────────────────────
// Build the prompt sent to Claude.
// We give it the parsed header data + protocol
// results so it can make an informed judgement.
// ─────────────────────────────────────────────
function buildPrompt(parsed, spfResult, dkimResult, dmarcResult, content = '') {
  const domainMismatch = parsed.fromDomain !== parsed.envelopeDomain;

  return `You are an email security analyst specialising in phishing and spoofing detection.

Analyse the following email header data and authentication results, then classify the email.

=== EMAIL HEADER DATA ===
From (visible):     ${parsed.from || '—'}
From Email:         ${parsed.fromEmail || '—'}
From Domain:        ${parsed.fromDomain || '—'}
Envelope Domain:    ${parsed.envelopeDomain || '—'}
Sender IP:          ${parsed.senderIP || '—'}
Subject:            ${parsed.subject || '(no subject)'}
Date:               ${parsed.date || '—'}
Reply-To:           ${parsed.replyTo || '(none)'}
Domain mismatch:    ${domainMismatch ? 'YES — From domain differs from envelope domain' : 'No'}
DKIM Selector:      ${parsed.dkimSignature?.s || '(none)'}
DKIM Signing Domain:${parsed.dkimSignature?.d || '(none)'}

=== EMAIL CONTENT ===
${content || '(no body provided)'}

=== AUTHENTICATION RESULTS ===
SPF:   ${spfResult?.result  || 'unknown'} — ${spfResult?.reason  || ''}
DKIM:  ${dkimResult?.result || 'unknown'} — ${dkimResult?.reason || ''}
DMARC: ${dmarcResult?.verdict || 'unknown'} (policy: ${dmarcResult?.policy || '—'}) — ${dmarcResult?.reason || ''}
SPF aligned:  ${dmarcResult?.spfAligned  ? 'yes' : 'no'}
DKIM aligned: ${dmarcResult?.dkimAligned ? 'yes' : 'no'}

=== YOUR TASK ===
Based on all the above, respond ONLY with a valid JSON object in this exact format.
Do not include markdown. Do not include trailing commas. Do not include newlines inside string values (use \n if needed).
Output JSON on a single line.

{
  "classification": "safe" | "suspicious" | "phishing" | "spoofing",
  "confidence": <integer 0-100>,
  "redFlags": ["flag 1", "flag 2", ...],
  "explanation": "<2-3 sentence plain English summary for a non-technical user>",
  "technicalSummary": "<1-2 sentence technical summary for a security analyst>",
  "recommendation": "deliver" | "review" | "delete" | "report"
}

Classification guide:
- "safe"       — all checks pass, no suspicious signals
- "suspicious" — some checks fail or minor red flags present, needs review
- "phishing"   — strong indicators of a phishing attempt (fake sender, urgent subject, domain mismatch)
- "spoofing"   — domain/sender is clearly forged (SPF/DKIM/DMARC all fail with misalignment)

Confidence guide:
- 90–100: very high certainty
- 70–89:  likely
- 50–69:  possible, needs more context
- 0–49:   uncertain

Respond with ONLY the JSON object. No explanation outside the JSON. No markdown code fences.`;
}

// ─────────────────────────────────────────────
// MAIN EXPORT: checkEmailWithAI
//
// Calls the Anthropic API and returns the AI analysis.
// Falls back gracefully if the API is unavailable.
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
      headers: {
        'Content-Type':      'application/json',
      },
      body: JSON.stringify({
        contents: [
          { role: 'user', parts: [{ text: prompt }] }
        ],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 1000,
          responseMimeType: 'application/json',
        },
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      logger.error(`AI checker: API error ${response.status} — ${err}`);
      return fallbackResult('API error — AI analysis unavailable');
    }

    const data = await response.json();

    const raw = data.candidates
      ?.flatMap(c => c.content?.parts || [])
      .map(p => p.text || '')
      .join('') || '';

    // Parse the JSON response
    const cleaned = raw.replace(/```json|```/g, '').trim();
    const jsonBlockMatch = cleaned.match(/\{[\s\S]*\}/);
    const jsonText = jsonBlockMatch ? jsonBlockMatch[0] : cleaned;

    const sanitizeJsonText = (input) => {
      let out = '';
      let inString = false;
      let escape = false;

      for (const ch of input) {
        if (escape) {
          out += ch;
          escape = false;
          continue;
        }

        if (ch === '\\') {
          out += ch;
          escape = true;
          continue;
        }

        if (ch === '"') {
          inString = !inString;
          out += ch;
          continue;
        }

        if (inString && (ch === '\n' || ch === '\r' || ch === '\t')) {
          out += ch === '\t' ? '\\t' : '\\n';
          continue;
        }

        out += ch;
      }

      return out;
    };

    let result;
    try {
      result = JSON.parse(sanitizeJsonText(jsonText));
    } catch (parseErr) {
      const repaired = sanitizeJsonText(jsonText)
        .replace(/([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:/g, '$1"$2":')
        .replace(/'([^']*)'/g, '"$1"');
      try {
        result = JSON.parse(repaired);
      } catch (repairErr) {
        result = extractLooseResult(cleaned);
      }
    }

    logger.info(`AI checker: classification=${result.classification}, confidence=${result.confidence}`);
    return { success: true, ...result };

  } catch (err) {
    logger.error(`AI checker: failed — ${err.message}`);
    return fallbackResult(`AI analysis failed: ${err.message}`);
  }
}

// Returns a safe fallback when the API call fails
// so the rest of the pipeline still works fine
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

function extractLooseResult(text) {
  const pick = (re, fallback = '') => {
    const match = text.match(re);
    return match ? match[1].trim() : fallback;
  };

  const classification = pick(/classification\s*[:=]\s*"?([a-zA-Z]+)"?/i, 'unknown').toLowerCase();
  const confidenceRaw = pick(/confidence\s*[:=]\s*(\d{1,3})/i, '0');
  const confidence = Math.max(0, Math.min(100, parseInt(confidenceRaw, 10) || 0));
  const recommendation = pick(/recommendation\s*[:=]\s*"?([a-zA-Z]+)"?/i, 'review').toLowerCase();

  const explanation = pick(
    /explanation\s*[:=]\s*"([\s\S]*?)"(?=\s*,\s*\w+\s*:|\s*\})/i,
    pick(/explanation\s*[:=]\s*([\s\S]*?)(?=\n\s*\w+\s*:|\n\s*\}|$)/i, 'AI analysis returned an invalid JSON response.')
  );
  const technicalSummary = pick(
    /technicalSummary\s*[:=]\s*"([\s\S]*?)"(?=\s*,\s*\w+\s*:|\s*\})/i,
    pick(/technicalSummary\s*[:=]\s*([\s\S]*?)(?=\n\s*\w+\s*:|\n\s*\}|$)/i, 'Invalid JSON from model.')
  );

  const redFlagsBlock = pick(/redFlags\s*[:=]\s*\[([\s\S]*?)\]/i, '');
  const redFlags = redFlagsBlock
    ? redFlagsBlock
        .split(',')
        .map(f => f.replace(/^[\s\"']+|[\s\"']+$/g, ''))
        .filter(Boolean)
    : [];

  if (!redFlags.length) {
    const bulletFlags = text
      .split(/\r?\n/)
      .filter(line => /^\s*[-*•]\s+/.test(line))
      .map(line => line.replace(/^\s*[-*•]\s+/, '').trim())
      .filter(Boolean);
    if (bulletFlags.length) redFlags.push(...bulletFlags);
  }

  return {
    classification,
    confidence,
    redFlags,
    explanation,
    technicalSummary,
    recommendation,
  };
}

module.exports = { checkEmailWithAI };