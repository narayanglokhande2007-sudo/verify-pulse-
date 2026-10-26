import crypto from 'crypto';

const MAX_EXTERNAL_ANALYSIS_LENGTH = 12000;

const INVISIBLE_OR_DIRECTIONAL = /[\u200B-\u200D\uFEFF\u2060\u00A0\u180E]/g;

// Match an actual credential value only when it is associated with a credential label.
// This intentionally does not match educational phrases such as "never share OTP/PIN".
const CREDENTIAL_VALUE_PATTERN = /\b(?:otp|one[-\s]?time(?:\s+password)?|passcode|pin)\s*(?:(?:is|code|number|no\.?)\s*|[:=\-]\s*)\d{4,8}\b|\bpassword\s*(?:(?:is|code|value)\s*|[:=\-]\s*)[A-Za-z0-9!@#$%^&*]{6,}\b|\b(?:otp|one[-\s]?time(?:\s+password)?|passcode|pin)\s+\d{4,8}\b|(?<![\w\u0900-\u097F])(?:ओटीपी|पिन|पासवर्ड)\s*(?:(?:है|नंबर|कोड)\s*|[:=\-]\s*)?\d{4,8}\b/gi;
const LABELLED_GOVERNMENT_ID_PATTERN = /\b(?:aadhaar|aadhar|uid(?:ai)?|pan|government id)\s*(?:(?:is|number|no\.?)\s*|[:=\-]\s*)?(?:\d{4}[ -]?\d{4}[ -]?\d{4}|[A-Z]{5}[0-9]{4}[A-Z])\b/gi;

const BANK_ACCOUNT_PATTERN = /\b(?:account|a\/?c|acct|khata|acc)(?:\s*(?:no\.?|number|#|is)?\s*[:=\-]?\s*)\d{9,18}\b/gi;
const CVV_EXPIRY_PATTERN = /\b(?:cvv|cvc|security\s*code)\s*(?:[:=\-]?\s*)\d{3,4}\b|\b(?:exp(?:iry)?(?:\s*date)?|valid\s*thru)\s*(?:[:=\-]?\s*)(?:0[1-9]|1[0-2])\/?(?:\d{2}|\d{4})\b/gi;
const DRIVING_LICENSE_PATTERN = /\b(?:dl|driving\s*licen[sc]e|licen[sc]e)\s*(?:no\.?|number|is)?\s*[:=\-]?\s*[A-Z]{2}[ -]?[0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{7}\b|\b[A-Z]{2}\d{13,15}\b/gi;
const VOTER_EPIC_PATTERN = /\b(?:voter\s*id|epic(?:\s*no\.?)?)\s*[:=\-]?\s*[A-Z]{3}[0-9]{7}\b/gi;
const UNIVERSAL_UPI_VPA_PATTERN = /\b[A-Za-z0-9._-]+@[A-Za-z0-9_-]{2,32}\b/gi;

const REDACTION_RULES = [
  // Redact labelled OTP/PIN/password and CVV/expiry values before any external analysis.
  { pattern: CREDENTIAL_VALUE_PATTERN, replacement: '[REDACTED_CREDENTIAL]' },
  { pattern: CVV_EXPIRY_PATTERN, replacement: '[REDACTED_CREDENTIAL]' },
  // Payment card numbers and bank account numbers (including spaces or hyphens).
  { pattern: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[REDACTED_PAYMENT_NUMBER]' },
  { pattern: BANK_ACCOUNT_PATTERN, replacement: '[REDACTED_PAYMENT_NUMBER]' },
  // Aadhaar, Indian PAN cards, Driving Licenses & Voter IDs (DPDP Act 2023).
  { pattern: /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, replacement: '[REDACTED_GOVERNMENT_ID]' },
  { pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/gi, replacement: '[REDACTED_GOVERNMENT_ID]' },
  { pattern: DRIVING_LICENSE_PATTERN, replacement: '[REDACTED_GOVERNMENT_ID]' },
  { pattern: VOTER_EPIC_PATTERN, replacement: '[REDACTED_GOVERNMENT_ID]' },
  // E-mail addresses must be redacted BEFORE UPI VPAs so domain emails with hyphens/dots are not fragmented
  { pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: '[REDACTED_EMAIL]' },
  // UPI Virtual Payment Address (VPA) handles (e.g., borrower@paytm, user@oksbi, custom handles)
  { pattern: UNIVERSAL_UPI_VPA_PATTERN, replacement: '[REDACTED_UPI_ID]' },
  // Indian Phone Numbers
  { pattern: /(?<!\d)(?:(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}|(?:\+91[\s-]?|0)?[6-9]\d{9})(?!\d)/g, replacement: '[REDACTED_PHONE]' }
];

export function sanitizeForExternalAnalysis(input) {
  // Normalize Unicode and eliminate zero-width evasion artifacts
  let sanitized = String(input || '').normalize('NFKC').replace(INVISIBLE_OR_DIRECTIONAL, '');
  for (const rule of REDACTION_RULES) {
    sanitized = sanitized.replace(rule.pattern, rule.replacement);
  }

  // Query strings, fragments, and basic auth credentials may contain tracking or session data.
  // Preserve the host and path for scam analysis while removing those volatile identifiers.
  sanitized = sanitized.replace(/https?:\/\/[^\s"']+/gi, (value) => {
    try {
      const url = new URL(value);
      url.username = '';
      url.password = '';
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
