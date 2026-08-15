import crypto from 'crypto';

const MAX_EXTERNAL_ANALYSIS_LENGTH = 12000;

// Match an actual credential value only when it is associated with a credential label.
// This intentionally does not match educational phrases such as "never share OTP/PIN".
const CREDENTIAL_VALUE_PATTERN = /\b(?:otp|one[-\s]?time(?:\s+password)?|passcode|pin)\s*(?:(?:is|code|number|no\.?)\s*|[:=\-]\s*)\d{4,8}\b|\bpassword\s*(?:(?:is|code|value)\s*|[:=\-]\s*)[A-Za-z0-9!@#$%^&*]{6,}\b|\b(?:otp|one[-\s]?time(?:\s+password)?|passcode|pin)\s+\d{4,8}\b/gi;
const LABELLED_GOVERNMENT_ID_PATTERN = /\b(?:aadhaar|aadhar|uid(?:ai)?|government id)\s*(?:(?:is|number|no\.?)\s*|[:=\-]\s*)?(?:\d{4}[ -]?\d{4}[ -]?\d{4})\b/gi;

const REDACTION_RULES = [
  // Redact labelled OTP/PIN/password values before any external analysis.
  { pattern: CREDENTIAL_VALUE_PATTERN, replacement: '[REDACTED_CREDENTIAL]' },
  // Payment card numbers, including spaces or hyphens.
  { pattern: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[REDACTED_PAYMENT_NUMBER]' },
  // Aadhaar-like 12-digit values. This is intentionally broad to avoid disclosure.
  { pattern: /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, replacement: '[REDACTED_GOVERNMENT_ID]' },
  // E-mail addresses and phone numbers are not necessary for scam classification.
  { pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: '[REDACTED_EMAIL]' },
  { pattern: /(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)/g, replacement: '[REDACTED_PHONE]' }
];

export function sanitizeForExternalAnalysis(input) {
  let sanitized = String(input || '');
  for (const rule of REDACTION_RULES) {
    sanitized = sanitized.replace(rule.pattern, rule.replacement);
  }

  // Query strings and fragments may contain tracking or session data. Preserve the
  // host and path for scam analysis while removing those volatile identifiers.
  sanitized = sanitized.replace(/https?:\/\/[^\s"']+/gi, (value) => {
    try {
      const url = new URL(value);
      url.search = '';
      url.hash = '';
      return url.toString();
    } catch {
      return value;
    }
  });

  return sanitized.slice(0, MAX_EXTERNAL_ANALYSIS_LENGTH);
}

export function hasCredentialLikeData(input) {
  const value = String(input || '');
  CREDENTIAL_VALUE_PATTERN.lastIndex = 0;
  LABELLED_GOVERNMENT_ID_PATTERN.lastIndex = 0;
  return CREDENTIAL_VALUE_PATTERN.test(value)
    || /\b(?:\d[ -]*?){13,19}\b/.test(value)
    // Generic 12-digit values are still redacted before external analysis, but do
    // not force a CAUTION verdict because legitimate UTR/UPI references can also
    // contain 12 digits. A labelled Aadhaar/UID value remains a blocking signal.
    || LABELLED_GOVERNMENT_ID_PATTERN.test(value);
}

export function createPrivacyReceipt(originalInput, sanitizedInput) {
  return {
    externalAnalysisRedacted: originalInput !== sanitizedInput,
    inputFingerprint: crypto.createHash('sha256').update(String(originalInput || '')).digest('hex'),
    // This receipt is safe to log only if the application policy allows it. Do not
    // log originalInput, request bodies, credentials, OTPs, or uploaded file data.
    policyVersion: 'vp-privacy-2'
  };
}
