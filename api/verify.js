// api/verify.js - VerifyPulse Backend with 200+ trusted domains whitelist
import { randomUUID } from 'node:crypto';
import { hasCredentialLikeData, sanitizeForExternalAnalysis } from '../lib/privacy_guard.js';
import { enforceRateLimit, getConfiguredLimit, setRateLimitHeaders } from '../lib/security_controls.js';
import { fetchJsonWithTimeout, logScanReliabilityEvent, runProviderAttempt } from '../lib/scan_reliability.js';
import { analyzeMessageForensics, canonicalizeUrl, extractUrlCandidates } from '../lib/url_forensics.js';
import { analyzeIntentForensics } from '../lib/intent_forensics.js';
import { calibrateDecision } from '../lib/decision_calibration.js';
import { createShadowEvaluation } from '../lib/shadow_evaluation.js';
import { lookupThreatIntelligence } from '../lib/threat_intelligence.js';
import { lookupHistoricalReputation } from '../lib/historical_reputation.js';
import { createRequestBudget } from '../lib/request_budget.js';
import { getPulseCoreLocalGuidance } from '../lib/pulsecore_local_guidance.js';

const threatFeedCache = { values: [], expiresAt: 0 };

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const rateLimit = enforceRateLimit(req, {
    scope: 'verify',
    limit: getConfiguredLimit('VERIFYPULSE_VERIFY_RATE_LIMIT_MAX', 20),
  });
  setRateLimitHeaders(res, rateLimit);
  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: 'RATE_LIMITED',
      message: 'Too many verification requests. Please retry shortly.',
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    });
  }

  const { text, checkType, fileData, externalProcessingConsent = false } = req.body || {};
  const supportedCheckTypes = new Set(['chatbot', 'news', 'password', 'scam', 'phishing', 'gmail', 'url', 'unified', 'phone', 'upi']);
  if (typeof text !== 'string' || !text.trim() || typeof checkType !== 'string') return res.status(400).json({ error: 'Missing text or checkType' });
  if (text.length > 12_000) return res.status(413).json({ error: 'INPUT_TOO_LARGE', message: 'Text input exceeds the 12,000 character safety limit.' });
  if (!supportedCheckTypes.has(checkType)) return res.status(400).json({ error: 'UNSUPPORTED_CHECK_TYPE' });
  if (fileData && (typeof fileData.base64 !== 'string' || fileData.base64.length > 4_000_000 || !/^image\/[a-z0-9.+-]+$|^audio\/[a-z0-9.+-]+$/i.test(String(fileData.mimeType || '')))) {
    return res.status(400).json({ error: 'INVALID_FILE_INPUT', message: 'Only image or audio files within the configured size limit can be analysed.' });
  }
  const externalAnalysisText = sanitizeForExternalAnalysis(text);
  const GROQ_KEY = process.env.GROQ_API_KEY;
  // Groq retired llama-3.3-70b-versatile on 2026-08-16 for free/developer use.
  // Keep this configurable, but use Groq's current production replacement by default.
  const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY;
  // Optional commercial-safe replacement for deprecated Safe Browsing v4.
  // No Web Risk call is made unless the user explicitly configures this key.
  const WEB_RISK_KEY = process.env.GOOGLE_WEB_RISK_API_KEY;
  const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;
  const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
  const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001';
  const requestId = randomUUID();
  const requestBudget = createRequestBudget();
  res.setHeader('X-VerifyPulse-Request-Id', requestId);
  const evidenceSources = [];
  let shadowIntentForensics = null;
  let shadowUrlForensics = null;
  function getShadowSignals() {
    if (!shadowIntentForensics) shadowIntentForensics = analyzeIntentForensics(externalAnalysisText);
    if (!shadowUrlForensics) shadowUrlForensics = analyzeMessageForensics(externalAnalysisText);
    return { intentForensics: shadowIntentForensics, urlForensics: shadowUrlForensics };
  }
  function normalizeVerdict(value) {
    const verdict = String(value || '').trim().toUpperCase().replace(/[\s-]+/g, '_');
    if (['SAFE', 'LEGITIMATE', 'LEGIT', 'NO_SCAM', 'BENIGN'].includes(verdict)) return 'SAFE';
    if (['DANGEROUS', 'SCAM', 'FRAUD', 'PHISHING', 'MALICIOUS', 'HIGH_RISK'].includes(verdict)) return 'DANGEROUS';
    if (['SUSPICIOUS', 'POTENTIAL_SCAM', 'POTENTIAL_FRAUD', 'RISKY', 'UNCERTAIN'].includes(verdict)) return 'SUSPICIOUS';
    if (['NEEDS_VERIFICATION', 'VERIFY', 'REVIEW_REQUIRED'].includes(verdict)) return 'NEEDS_VERIFICATION';
    if (['CAUTION', 'CONSENT_REQUIRED'].includes(verdict)) return verdict;
    // Unknown provider strings must never fall through to an implied SAFE result.
    return 'NEEDS_VERIFICATION';
  }

  function safeResult(r) {
    r.verdict = normalizeVerdict(r.verdict);
    if (typeof r.findings === 'string') r.findings = [r.findings];
    if (!Array.isArray(r.findings)) r.findings = [];
    if (typeof r.whatToDo === 'string') r.whatToDo = [r.whatToDo];
    if (!Array.isArray(r.whatToDo)) r.whatToDo = [];
    if (!Array.isArray(r.evidenceSources)) r.evidenceSources = [...evidenceSources];
    r.evidenceSources = [...new Set(r.evidenceSources)];
    if (r.forensics && typeof r.forensics === 'object') {
      r.forensics.version = r.forensics.version || 'vp-forensics-1';
    }
    r.requestId = requestId;
    r.explainability = buildExplainability(r);
    r.decisionCalibration = calibrateDecision({
      verdict: r.verdict,
      confidence: r.confidence,
      evidenceSources: r.evidenceSources
    });
    r.shadowEvaluation = createShadowEvaluation({
      verdict: r.verdict,
      evidenceSources: r.evidenceSources,
      ...getShadowSignals()
    });
    r.enterpriseEvidence = {
      schemaVersion: 'vp-enterprise-evidence-1',
      correlationId: requestId,
      verdict: r.verdict,
      riskBand: r.decisionCalibration.riskBand,
      decisionBasis: r.decisionCalibration.decisionBasis,
      evidenceSources: r.evidenceSources,
      explainabilityVersion: r.explainability.version,
      privacyStatement: 'This audit envelope contains decision metadata and evidence labels only; raw scanned content and credentials are not retained.'
    };
    r.decisionMetadata = {
      version: 'vp-decision-1',
      evidenceSourceCount: r.evidenceSources.length,
      assessmentType: r.explainability.assessmentType,
      elapsedMs: requestBudget.elapsedMs(),
      remainingBudgetMs: requestBudget.remainingMs()
    };
    return r;
  }
  // ----- 200+ trusted domains list (all official brands) -----
  function isTrustedMessage(msg) {
    const trustedDomains = [
      // Banks
      'sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com',
      'pnb.in', 'bankofbaroda.in', 'axisbank.com', 'kotak.com', 'idfcbank.com',
      'canarabank.com', 'unionbankofindia.co.in', 'indianbank.in', 'centralbankofindia.co.in',
      'bandhanbank.com', 'yesbank.in', 'rbi.org.in', 'nabard.org',
      // Payment / Fintech
      'phonepe.com', 'paytm.com', 'npci.org.in', 'razorpay.com', 'cashfree.com', 'billdesk.com',
      'ccavenue.com', 'instamojo.com', 'freedo.in', 'mobikwik.com', 'amazon.in',
      // Stock / Trading
      'zerodha.com', 'angelone.in', 'groww.in', 'upstox.com', '5paisa.com',
      'icicidirect.com', 'hdfcsec.com', 'kotaksecurities.com', 'motilaloswal.com',
      'iifl.com', 'sharekhan.com', 'indiabulls.com', 'sbinsecurities.in', 'nseindia.com', 'bseindia.com',
      // Education / Edtech
      'vedantu.com', 'byjus.com', 'unacademy.com', 'physicswallah.com', 'pw.live',
      'khanacademy.org', 'coursera.org', 'udemy.com', 'upgrad.com', 'codingninjas.com',
      'scaler.com', 'prepbytes.com', 'geeksforgeeks.org', 'toppr.com', 'meritnation.com',
      // Telecom
      'airtel.in', 'vi.in', 'jio.com', 'vodafone.in', 'reliancejio.com', 'bsnl.co.in',
      // Social / Communication
      'whatsapp.com', 'telegram.org', 'signal.org', 'facebook.com', 'instagram.com',
      'x.com', 'linkedin.com', 'youtube.com', 'twitter.com', 'snapchat.com',
      // E‑commerce & Delivery
      'flipkart.com', 'myntra.com', 'tatacliq.com', 'ajio.com', 'nykaa.com',
      'zomato.com', 'swiggy.com', 'amazon.in', 'amazon.com', 'ebay.com', 'shopify.com',
      // Government / Utility
      'gov.in', 'nic.in', 'india.gov.in', 'mygov.in', 'digilocker.gov.in', 'epfo.gov.in',
      'gst.gov.in', 'passportindia.gov.in', 'irctc.co.in', 'indianrail.gov.in',
      // Insurance
      'licindia.in', 'policybazaar.com', 'coverfox.com', 'renewbuy.com', 'turtlemint.com',
      'acko.com', 'digitinsurance.com', 'bajajallianz.com', 'hdfcergo.com',
      // News / Media (often spoofed)
      'timesofindia.com', 'hindustantimes.com', 'indiatoday.com', 'ndtv.com', 'thehindu.com',
      'aajtak.in', 'zeenews.com', 'republicworld.com', 'news18.com',
      // Healthcare / Pharmacy
      'tata1mg.com', 'netmeds.com', 'pharmeasy.in', 'apollopharmacy.in', 'practo.com',
      // Real Estate / Utilities
      'magicbricks.com', '99acres.com', 'housing.com', 'no-broker.in', 'bijlibachao.com',
      'torrentpower.com', 'adb.org',
      // Educational institutions (university domains often targeted)
      'du.ac.in', 'jnu.ac.in', 'bhu.ac.in', 'amu.ac.in', 'iitd.ac.in', 'iitm.ac.in',
      'iitb.ac.in', 'iitk.ac.in', 'niti.gov.in', 'ugc.ac.in', 'aicte-india.org',
      // Additional trusted (Allen, etc.)
      'allen.ac.in', 'allen.in', 'd.sfmsg.co'
    ];
    // VerifyPulse first-party URLs are deliberately exact-host matches. Do not
    // trust arbitrary subdomains: a future staging, tenant, or misconfigured
    // host must not become SAFE merely because it ends with verify-pulse.com.
    const exactTrustedHostnames = new Set(['verify-pulse.com', 'www.verify-pulse.com']);
    const urls = extractUrlCandidates(msg).map(canonicalizeUrl).filter(Boolean);
    // An official domain reference does not make a message safe when it asks for
    // credentials, money, an urgent action, or an untrusted contact channel.
    // This prevents a scammer from attaching a legitimate link as camouflage.
    const riskyAction = /\b(?:otp|pin|cvv|password|card details?|bank account details?|screen share|remote access|collect request|verification fee|processing fee|pay now|payment|urgent|immediately|within \d+|freeze|blocked|arrest|whatsapp|telegram|reply yes|call now)\b|तुरंत|ओटीपी|पिन|చెల్లించ|వెంటనే/i.test(String(msg || ''));

    // A text-only message cannot prove that its claimed brand or authority is authentic.
    // It must continue to the scam-analysis flow rather than receiving a SAFE shortcut.
    if (urls.length === 0 || riskyAction) return false;
    for (const parsedUrl of urls) {
      const hostname = parsedUrl.hostname;
      const matched = exactTrustedHostnames.has(hostname)
        || trustedDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
      if (!matched) return false;
    }
    return true;
  }

  function assessTrustedDomainMessageAmbiguity(msg) {
    const value = String(msg || '').trim();
    if (!value) return null;

    // A real official URL proves only the hostname. It does not authenticate who
    // sent a promotional message or establish that a time-limited offer is current.
    // Keep ordinary official links SAFE, but require independent verification when
    // an unverified sender combines an official-domain link with a promotion/claim.
    const promotion = /\b(?:free|offer|reward|prize|gift|cashback|coupon|congratulations|exclusive|bonus|deal|data pack|recharge)\b/i.test(value);
    const action = /\b(?:claim|redeem|click|tap|open|visit|collect|get now|activate)\b/i.test(value);
    if (!promotion || !action) return null;

    return {
      verdict: 'NEEDS_VERIFICATION',
      scamType: 'Promotional Message Requires Sender Verification',
      confidence: 60,
      analysis: 'The link hostname matches a trusted registry, but the promotional offer and sender cannot be authenticated from the message alone. This is not a scam confirmation and not a SAFE result; verify the offer in the official app or by manually entering the official website.',
      findings: ['The link hostname matches the trusted-domain registry.', 'The message contains a promotion or reward and asks you to take an action.', 'A text message cannot prove that the sender or offer is authentic or current.'],
      whatToDo: ['Open the official app or manually type the official website instead of using the message link.', 'Check whether the same offer appears in your authenticated account before claiming, paying, or sharing information.'],
      evidenceSources: ['Trusted domain registry', 'Local sender-authentication policy']
    };
  }

  function assessTextOnlySocialEngineering(msg) {
    const urls = String(msg || '').match(/https?:\/\/[^\s]+/g) || [];
    if (urls.length > 0) return null;

    const value = String(msg || '');
    const signals = {
      authorityClaim: /\b(?:rbi|reserve bank|income tax|cbi|cyber crime|cybercell|police|sebi|gst|epfo|customs|court|government)\b/i.test(value),
      sensitiveAction: /\b(?:bank account details?|otp|pin|cvv|card details?|aadhaar|id proof|kyc|video verification|screen share)\b/i.test(value),
      pressure: /\b(?:within|minutes?|hours?|immediately|urgent|freeze|blocked|suspend|arrest|fir|penalty)\b/i.test(value),
      untrustedContact: /\b(?:whatsapp|reply\s+(?:yes|ok)|verification call|video call|collect request)\b/i.test(value),
      paymentDemand: /(?:₹|\brs\.?\s*\d|\binr\s*\d|payment|collect request|processing fee|verification fee)/i.test(value),
      secrecyDemand: /\b(?:kisi ko(?:\s+bhi)?\s+(?:mat|mana)|do not tell|keep this secret)\b/i.test(value)
    };
    const score = Object.values(signals).filter(Boolean).length;
    const highRisk = signals.authorityClaim
      && (signals.untrustedContact || signals.paymentDemand || signals.secrecyDemand || (signals.sensitiveAction && signals.pressure))
      && score >= 2;

    return highRisk ? { score, signals } : null;
  }

  function assessAmbiguousLegitimateNotification(msg) {
    const value = String(msg || '').trim();
    const normalized = value.toLowerCase();
    const urls = value.match(/https?:\/\/[^\s]+/g) || [];
    if (!value || urls.length > 0) return null;

    // This policy deliberately avoids calling a message SAFE when the sender cannot
    // be authenticated. It identifies common legitimate-notification structures
    // only when no payment, credential, urgency, installation, or contact red flag
    // is present, then asks the user to verify in the official app/channel.
    const benignEvent = /\b(?:credited|debited|transaction (?:successful|completed)|upi ref(?:erence)?|utr(?: no\.?| number)?|available balance|statement|cashback credited|refund credited|benefit credited|dbt credited|card ending|merchant|credit limit updated)\b/i.test(value);
    const benignContext = /\b(?:npci|upi|dbt|direct benefit transfer|bank|account|cashback|refund|transaction|card|merchant|credit limit)\b/i.test(value);
    const actionRisk = /\b(?:click|tap|open link|verify|re-?kyc|update|install|download|call|whatsapp|telegram|reply|share|otp|pin|cvv|password|screen share|collect request|pay now|processing fee)\b/i.test(value);
    const urgencyRisk = /\b(?:urgent|immediately|within \d+|last chance|blocked|freeze|suspend|penalty|arrest)\b/i.test(value);
    const executableRisk = /\.(?:apk|exe|msi)\b/i.test(normalized);

    if (!benignEvent || !benignContext || actionRisk || urgencyRisk || executableRisk) return null;
    return {
      verdict: 'NEEDS_VERIFICATION',
      scamType: 'Unauthenticated Financial Notification',
      confidence: 58,
      analysis: 'This looks like a routine financial or government-benefit notification and does not contain a direct fraud request. Verify the transaction independently in the official banking, UPI, or government app before relying on it.',
      findings: ['No direct payment, credential-sharing, link, installation, contact-channel, or urgency red flag was detected.', 'The message sender and transaction cannot be authenticated from text alone.'],
      whatToDo: ['Check the relevant official app or account statement rather than replying to the message.', 'If the transaction is missing or unexpected, contact the organisation through an official website or helpline.'],
      evidenceSources: ['Local notification ambiguity rules']
    };
  }

  function buildExplainability(result) {
    const verdict = String(result.verdict || 'UNCERTAIN').toUpperCase();
    const sources = Array.isArray(result.evidenceSources) ? result.evidenceSources : [];
    const findings = Array.isArray(result.findings) ? result.findings.slice(0, 5) : [];
    const evidence = [];

    const googleReputationSource = sources.includes('Google Web Risk')
      ? 'Google Web Risk'
      : sources.includes('Google Safe Browsing')
        ? 'Google Safe Browsing'
        : null;
    if (googleReputationSource) {
      evidence.push({
        source: googleReputationSource,
        type: 'external-url-reputation',
        detail: verdict === 'DANGEROUS'
          ? 'The submitted URL matched a known malicious threat result.'
          : 'A URL reputation lookup completed; no threat match is implied by this entry alone.'
      });
    }
    if (sources.includes('Trusted domain registry')) {
      evidence.push({
        source: 'Trusted domain registry',
        type: 'deterministic-domain-match',
        detail: 'The parsed URL hostname matched the VerifyPulse trusted-domain registry.'
      });
    }
    if (sources.includes('Local social-engineering rules')) {
      evidence.push({
        source: 'Local social-engineering rules',
        type: 'deterministic-text-signals',
        detail: findings.length
          ? `Detected signals: ${findings.join(', ')}.`
          : 'A configured authority-impersonation risk rule was triggered.'
      });
    }
    if (sources.includes('Privacy guard')) {
      evidence.push({
        source: 'Privacy guard',
        type: 'local-data-protection-control',
        detail: verdict === 'CONSENT_REQUIRED'
          ? 'External file analysis was not started because explicit consent was missing.'
          : 'Potential credentials or identifiers were protected from external AI analysis.'
      });
    }
    if (sources.includes('Local high-confidence fallback rules')) {
      evidence.push({
        source: 'Local high-confidence fallback rules',
        type: 'deterministic-text-signals',
        detail: findings.length ? `Detected high-confidence signals: ${findings.join(', ')}.` : 'Configured high-confidence scam indicators were detected.'
      });
    }
    if (sources.includes('Local notification ambiguity rules')) {
      evidence.push({
        source: 'Local notification ambiguity rules',
        type: 'deterministic-verification-policy',
        detail: 'The message resembles a routine notification but lacks an independently authenticated sender or official-domain proof.'
      });
    }
    if (sources.includes('Local sender-authentication policy')) {
      evidence.push({
        source: 'Local sender-authentication policy',
        type: 'deterministic-verification-policy',
        detail: 'An official hostname does not authenticate the sender or prove that a promotional offer is current.'
      });
    }
    if (sources.includes('Local URL and brand forensics')) {
      evidence.push({
        source: 'Local URL and brand forensics',
        type: 'deterministic-url-brand-forensics',
        detail: findings.length ? `URL/brand indicators: ${findings.join(' ')}` : 'A local URL, brand, or intent mismatch was detected.'
      });
    }
    if (sources.includes('Local multilingual intent forensics')) {
      evidence.push({
        source: 'Local multilingual intent forensics',
        type: 'deterministic-payment-and-impersonation-signals',
        detail: findings.length ? `Detected intent indicators: ${findings.join(' ')}` : 'A high-confidence payment, impersonation, or remote-access combination was detected locally.'
      });
    }
    if (sources.includes('Historical multi-source threat reputation')) {
      evidence.push({
        source: 'Historical multi-source threat reputation',
        type: 'exact-historical-reputation-match',
        detail: 'The submitted URL or domain exactly matched VerifyPulse\'s retained multi-source historical threat-reputation index.'
      });
    }
    if (sources.includes('Source-aware threat intelligence')) {
      evidence.push({
        source: 'Source-aware threat intelligence',
        type: 'expiry-bounded-reputation-match',
        detail: 'The submitted URL or domain matched a current threat-intelligence indicator with preserved source and expiry metadata.'
      });
    }
    if (sources.includes('Service health monitor')) {
      evidence.push({
        source: 'Service health monitor',
        type: 'service-availability-status',
        detail: 'External model analysis did not return a usable verdict during this request. This is not a SAFE result.'
      });
    }
    if (evidence.length === 0) {
      evidence.push({
        source: 'Model-assisted assessment',
        type: 'model-generated-assessment',
        detail: 'No deterministic reputation match or trusted-domain shortcut was used for this verdict.'
      });
    }

    let summary;
    if (verdict === 'CAUTION' || verdict === 'CONSENT_REQUIRED') {
      summary = 'This result was produced by a privacy protection control, not by a scam classification.';
    } else if (googleReputationSource && verdict === 'DANGEROUS') {
      summary = 'A known-malicious URL reputation match contributed to this high-risk result.';
    } else if (sources.includes('Local sender-authentication policy')) {
      summary = 'The URL hostname is official, but the message sender and promotional offer cannot be authenticated from text alone, so independent verification is required.';
    } else if (sources.includes('Trusted domain registry')) {
      summary = 'The result is based on an exact parsed-hostname registry match; it does not authenticate a message sender.';
    } else if (sources.includes('Local notification ambiguity rules')) {
      summary = 'The message appears routine but cannot be authenticated from text alone, so VerifyPulse recommends independent verification rather than a SAFE verdict.';
    } else if (sources.includes('Local URL and brand forensics')) {
      summary = 'The result is based on deterministic URL, brand, and requested-action indicators rather than a model-only judgement.';
    } else if (sources.includes('Local multilingual intent forensics')) {
      summary = 'The result is based on deterministic multilingual payment, impersonation, or remote-access signals rather than a model-only judgement.';
    } else if (sources.includes('Historical multi-source threat reputation')) {
      summary = 'An exact retained historical threat-reputation match contributed to this evidence-backed risk result.';
    } else if (sources.includes('Source-aware threat intelligence')) {
      summary = 'A current, source-aware threat-intelligence match contributed to this evidence-backed risk result.';
    } else if (sources.includes('Local social-engineering rules') || sources.includes('Local high-confidence fallback rules')) {
      summary = 'The result is based on deterministic high-confidence social-engineering signals in the text.';
    } else if (sources.includes('Service health monitor')) {
      summary = 'External analysis was temporarily unavailable; this response does not assess the content as safe.';
    } else {
      summary = 'The result is model-assisted and should be treated as a risk assessment, not proof of fraud or safety.';
    }

    const hasDeterministicEvidence = sources.includes('Trusted domain registry')
      || sources.includes('Local social-engineering rules')
      || sources.includes('Local high-confidence fallback rules')
      || sources.includes('Local notification ambiguity rules')
      || sources.includes('Local sender-authentication policy')
      || sources.includes('Local URL and brand forensics')
      || sources.includes('Local multilingual intent forensics')
      || sources.includes('Source-aware threat intelligence')
      || sources.includes('Historical multi-source threat reputation')
      || (Boolean(googleReputationSource) && verdict === 'DANGEROUS');
    const isPrivacyProtection = sources.includes('Privacy guard');

    return {
      version: 'vp-explain-1',
      assessmentType: isPrivacyProtection
        ? 'privacy-protection'
        : sources.includes('Service health monitor')
          ? 'service-status'
          : hasDeterministicEvidence
            ? 'evidence-backed'
            : 'model-assisted',
      summary,
      evidence,
      limitations: [
        'A SAFE result does not authenticate the sender or guarantee future safety.',
        'A risk result should be verified through an official channel before taking action.'
      ]
    };
  }

  try {
    if (checkType === 'password' || hasCredentialLikeData(text)) {
      // Passwords, OTPs, PINs, payment data, and government IDs must not be
      // transmitted to external AI services or represented as safe merely because
      // they were received by this endpoint.
      return res.status(200).json(safeResult({
        verdict: 'CAUTION',
        confidence: 100,
        analysis: 'Sensitive credentials or identifiers were detected. VerifyPulse did not send them to external AI services.',
        findings: ['Never share passwords, OTPs, PINs, card details, or government identifiers with a website or an AI service.'],
        whatToDo: ['Change any credential that was already shared.', 'Contact the relevant bank or provider through its official channel if you believe the information was exposed.'],
        evidenceSources: ['Privacy guard']
      }));
    }
    // ----- CHATBOT: PulseCore -----
    if (checkType === 'chatbot') {
      const chatbotPrompt = `You are "PulseCore", a highly intelligent AI Security & Banking Expert for VerifyPulse.
CRITICAL GUARDRAILS:
1. DOMAIN RESTRICTION: You MUST ONLY talk about Indian Banking, Cybersecurity, Net Banking, Scams, and RBI guidelines.
2. OUT OF BOUNDS: If the user asks about ANYTHING else (like movies, weather, politics, general coding, sports, personal questions like "do you have a girlfriend", etc.), politely decline in the user's exact language and offer help with banking, cybersecurity, or net-banking safety.
3. LANGUAGE MASTERY: Reply in the exact language and script used by the user, including Hindi, Marathi, Bengali, Telugu, and Tamil where applicable.
4. TONE & FORMAT: Be conversational and professional. Use short paragraphs and bullets when helpful. Use at most two relevant professional emojis.
5. SAFETY: Do not request passwords, OTPs, PINs, card details, or government identifiers. Do not claim certainty when information needs official verification.`;
      const failedChatProviders = [];
      const chatAttempt = async ({ stage, provider, operation }) => {
        const timeoutMs = requestBudget.timeoutFor({ capMs: 2400, minimumMs: 500 });
        if (!timeoutMs) {
          failedChatProviders.push({ provider, errorCode: 'chat_budget_exhausted' });
          return null;
        }
        const attemptResult = await runProviderAttempt({ requestId, stage, provider, operation: () => operation(timeoutMs) });
        const reply = String(attemptResult.result || '').trim();
        if (attemptResult.ok && reply) return reply;
        failedChatProviders.push({ provider, errorCode: attemptResult.errorCode || 'empty_chat_reply' });
        return null;
      };
      const callGeminiChat = async (apiKey, timeoutMs) => {
        const data = await fetchJsonWithTimeout(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(apiKey)}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ systemInstruction: { parts: [{ text: chatbotPrompt }] }, contents: [{ role: 'user', parts: [{ text: externalAnalysisText }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 800 } })
        }, { provider: 'gemini', timeoutMs });
        return data.candidates?.[0]?.content?.parts?.map((part) => part?.text || '').join('').trim() || '';
      };
      const callGroqChat = async (apiKey, timeoutMs) => {
        const data = await fetchJsonWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: GROQ_MODEL, messages: [{ role: 'system', content: chatbotPrompt }, { role: 'user', content: externalAnalysisText }], temperature: 0.2, max_tokens: 800 })
        }, { provider: 'groq', timeoutMs });
        return String(data.choices?.[0]?.message?.content || '').trim();
      };
      const callAnthropicChat = async (apiKey, timeoutMs) => {
        const data = await fetchJsonWithTimeout('https://api.anthropic.com/v1/messages', {
          method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
          body: JSON.stringify({ model: ANTHROPIC_MODEL, max_tokens: 800, temperature: 0.2, system: chatbotPrompt, messages: [{ role: 'user', content: externalAnalysisText }] })
        }, { provider: 'anthropic', timeoutMs });
        return String(data.content?.find((block) => block?.type === 'text')?.text || '').trim();
      };
      const callOpenRouterChat = async (apiKey, timeoutMs) => {
        const data = await fetchJsonWithTimeout('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
          body: JSON.stringify({ model: 'openrouter/free', messages: [{ role: 'system', content: chatbotPrompt }, { role: 'user', content: externalAnalysisText }], temperature: 0.2, max_tokens: 800 })
        }, { provider: 'openrouter', timeoutMs });
        return String(data.choices?.[0]?.message?.content || '').trim();
      };

      const routes = [
        GEMINI_KEY && { stage: 'pulsecore_primary_chat', provider: 'gemini', operation: (timeoutMs) => callGeminiChat(GEMINI_KEY, timeoutMs) },
        GROQ_KEY && { stage: 'pulsecore_fallback_chat', provider: 'groq', operation: (timeoutMs) => callGroqChat(GROQ_KEY, timeoutMs) },
        ANTHROPIC_KEY && { stage: 'pulsecore_fallback_chat', provider: 'anthropic', operation: (timeoutMs) => callAnthropicChat(ANTHROPIC_KEY, timeoutMs) },
        OPENROUTER_KEY && { stage: 'pulsecore_fallback_chat', provider: 'openrouter', operation: (timeoutMs) => callOpenRouterChat(OPENROUTER_KEY, timeoutMs) }
      ].filter(Boolean);
      const localGuidance = getPulseCoreLocalGuidance(text);
      const localGuidanceResponse = () => {
        logScanReliabilityEvent({ requestId, stage: 'pulsecore_router', outcome: 'local_safety_guidance', errorCode: failedChatProviders.map((entry) => entry.errorCode).join(',') || 'provider_not_configured' });
        return res.status(200).json({
          reply: localGuidance,
          replyStatus: 'local_safety_guidance',
          failedProviders: failedChatProviders.map((entry) => ({ provider: entry.provider, errorCode: entry.errorCode }))
        });
      };
      for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
        const route = routes[routeIndex];
        const reply = await chatAttempt(route);
        if (reply) return res.status(200).json({ reply, replyStatus: 'available', replyProvider: route.provider });
        // For recognised safety topics, do not wait for a long all-provider chain.
        // Two bounded independent attempts preserve useful AI availability while
        // keeping the local trusted guidance reachable before a serverless timeout.
        if (localGuidance && routeIndex + 1 >= Math.min(2, routes.length)) return localGuidanceResponse();
      }
      if (localGuidance) return localGuidanceResponse();
      logScanReliabilityEvent({ requestId, stage: 'pulsecore_router', outcome: 'degraded_chat_response', errorCode: failedChatProviders.map((entry) => entry.errorCode).join(',') || 'provider_not_configured' });
      return res.status(200).json({
        reply: 'PulseCore ka live AI response abhi temporarily unavailable hai. Yeh security advice ya SAFE result nahi hai. Banking ya cyber-fraud matter ke liye official bank app, RBI guidance, ya 1930 ke through verify karein; thodi der baad phir try karein.',
        replyStatus: 'temporarily_unavailable',
        failedProviders: failedChatProviders.map((entry) => ({ provider: entry.provider, errorCode: entry.errorCode }))
      });
    }
    const textRisk = assessTextOnlySocialEngineering(text);
    if (textRisk && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      const activeSignals = Object.entries(textRisk.signals)
        .filter(([, present]) => present)
        .map(([name]) => name.replace(/([A-Z])/g, ' $1').toLowerCase());
      return res.status(200).json(safeResult({
        verdict: 'SUSPICIOUS',
        scamType: 'Potential Authority-Impersonation Scam',
        confidence: 82,
        analysis: 'This text makes an authority claim while asking for sensitive action, urgent action, money, secrecy, or an untrusted contact channel. Verify it only through an official channel you find independently.',
        findings: activeSignals,
        whatToDo: ['Do not reply, pay, share details, or join a verification call from this message.', 'Contact the claimed organisation through its official website or helpline.', 'Report suspected financial fraud promptly through 1930.'],
        evidenceSources: ['Local social-engineering rules']
      }));
    }

    const ambiguousNotification = assessAmbiguousLegitimateNotification(text);
    if (ambiguousNotification && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      return res.status(200).json(safeResult(ambiguousNotification));
    }

    // Deterministic high-confidence patterns run before external model calls.
    // This provides a fast protective response when the message includes multiple
    // unambiguous scam indicators, while ambiguous cases continue to model analysis.
    const earlyLocalRisk = assessHighConfidenceFallbackRisk(text);
    if (earlyLocalRisk && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      logScanReliabilityEvent({ requestId, stage: 'local_high_confidence_precheck', provider: 'local_rules', outcome: 'success' });
      return res.status(200).json(safeResult(earlyLocalRisk));
    }

    const intentForensics = analyzeIntentForensics(text);
    if (intentForensics.highRisk && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      logScanReliabilityEvent({ requestId, stage: 'local_multilingual_intent_forensics', provider: 'local_intent_forensics', outcome: 'success' });
      return res.status(200).json(safeResult({
        verdict: 'SUSPICIOUS',
        scamType: 'High-Confidence Payment or Impersonation Risk',
        confidence: Math.min(95, Math.max(82, intentForensics.score + 42)),
        analysis: 'VerifyPulse detected a high-confidence combination of payment, impersonation, remote-access, or UPI-receipt deception signals locally. Do not pay, approve, scan, install, or share credentials through this message.',
        findings: intentForensics.findings,
        whatToDo: ['Do not scan a QR code, enter a UPI PIN, approve a collect request, install an app, pay a fee, or share credentials based on this message.', 'Open the claimed organisation’s official app or website manually to verify the request.', 'Report suspected financial fraud promptly through 1930.'],
        evidenceSources: ['Local multilingual intent forensics'],
        intentForensics
      }));
    }

    // Run fresh and retained-history reputation checks together. Both are
    // bounded and fail-safe; a lookup outage never creates a SAFE result.
    const [historicalReputation, threatIntelligence] = await Promise.all([
      lookupHistoricalReputation(text),
      lookupThreatIntelligence(text)
    ]);
    if (historicalReputation.matched) {
      const strongestMatch = historicalReputation.matches[0];
      const highConfidence = strongestMatch.confidence >= 90 || strongestMatch.sourceCount >= 2;
      return res.status(200).json(safeResult({
        verdict: highConfidence ? 'DANGEROUS' : 'SUSPICIOUS',
        scamType: 'Historical Threat Reputation Match',
        confidence: Math.min(99, Math.max(70, strongestMatch.confidence)),
        analysis: 'The submitted link or domain exactly matches VerifyPulse\'s retained multi-source historical threat-reputation index. This is evidence-based risk information, not a guarantee that every unlisted link is safe.',
        findings: [
          `Matched ${strongestMatch.indicatorType} indicator for ${strongestMatch.hostname}.`,
          `Historical sources: ${strongestMatch.sources.join(', ') || 'recorded threat feed'}.`,
          `First recorded: ${strongestMatch.firstSeen || 'date unavailable'}; last recorded: ${strongestMatch.lastSeen || 'date unavailable'}.`
        ],
        whatToDo: ['Do not open the link, install files, make payments, or share credentials.', 'Use the official app or a manually entered official website to verify the claimed service.', 'Report suspected financial fraud promptly through 1930.'],
        evidenceSources: ['Historical multi-source threat reputation'],
        historicalReputation,
        threatIntelligence
      }));
    }
    if (threatIntelligence.matched) {
      const strongestMatch = threatIntelligence.matches[0];
      const highConfidence = strongestMatch.confidence >= 90 || strongestMatch.sourceCount >= 2;
      return res.status(200).json(safeResult({
        verdict: highConfidence ? 'DANGEROUS' : 'SUSPICIOUS',
        scamType: 'Threat Intelligence Reputation Match',
        confidence: Math.min(99, Math.max(75, strongestMatch.confidence)),
        analysis: 'The submitted link or domain matches a current threat-intelligence indicator. This result is based on provenance-aware reputation evidence and should be verified through an official channel before action.',
        findings: [`Matched ${strongestMatch.indicatorType} indicator for ${strongestMatch.hostname}.`, `Sources: ${strongestMatch.sources.join(', ') || 'recorded threat feed'}.`, `Indicator expiry: ${strongestMatch.expiresAt}.`],
        whatToDo: ['Do not open the link, install files, make payments, or share credentials.', 'Use the official app or a manually entered official website to verify the claimed service.', 'Report suspected financial fraud promptly through 1930.'],
        evidenceSources: ['Source-aware threat intelligence'],
        threatIntelligence
      }));
    }

    // ---- Cached live knowledge boost ----
    const recentScamURLs = await getRecentScamUrls();
    const knowledgeLine = recentScamURLs.length > 0 ? `\n\nLatest known phishing/scam URLs (for reference):\n${recentScamURLs.join('\n')}` : '';
    // Google URL-reputation check. Web Risk is preferred when explicitly configured;
    // the existing Safe Browsing v4 path remains a compatibility fallback only.
    if (['url', 'phishing', 'scam', 'gmail', 'unified'].includes(checkType) && (WEB_RISK_KEY || SAFE_BROWSING_KEY)) {
      try {
        const urls = text.match(/https?:\/\/[^\s]+/g) || [];
        for (let urlStr of urls) {
          const cleanUrl = urlStr.replace(/[.,;)]+$/, '');
          const googleReputationTimeout = requestBudget.timeoutFor({ capMs: 800, minimumMs: 300 });
          if (!googleReputationTimeout) break;
          const reputationSource = WEB_RISK_KEY ? 'Google Web Risk' : 'Google Safe Browsing';
          const googleResult = WEB_RISK_KEY
            ? await checkWithWebRisk(cleanUrl, WEB_RISK_KEY, googleReputationTimeout)
            : await checkWithSafeBrowsing(cleanUrl, SAFE_BROWSING_KEY, googleReputationTimeout);
          if (googleResult?.checked) evidenceSources.push(reputationSource);
          if (googleResult?.found) return res.status(200).json(safeResult(googleResult));
        }
      } catch (e) {
        console.error('Google URL reputation check failed:', e.message);
      }
    }
    // A SAFE shortcut is allowed only for a parsed URL whose canonical hostname
    // matches the registry. Google URL-reputation evidence is included only when a lookup ran.
    if (['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType) && isTrustedMessage(text)) {
      const trustedDomainAmbiguity = assessTrustedDomainMessageAmbiguity(text);
      if (trustedDomainAmbiguity) {
        return res.status(200).json(safeResult({
          ...trustedDomainAmbiguity,
          evidenceSources: [...evidenceSources, ...trustedDomainAmbiguity.evidenceSources]
        }));
      }
      return res.status(200).json(safeResult({
        verdict: 'SAFE',
        scamType: 'Trusted Domain URL',
        confidence: 99,
        analysis: 'The submitted URL matches the trusted-domain registry. This is not an authentication of the message sender.',
        findings: ['Parsed hostname matches the trusted-domain registry.'],
        whatToDo: ['Use only official contact channels for sensitive account actions.'],
        evidenceSources: [...evidenceSources, 'Trusted domain registry']
      }));
    }
    const forensics = analyzeMessageForensics(text);
    if (forensics.highRisk && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      logScanReliabilityEvent({ requestId, stage: 'local_url_brand_forensics', provider: 'local_forensics', outcome: 'success' });
      return res.status(200).json(safeResult({
        verdict: 'SUSPICIOUS',
        scamType: 'URL, Brand, or Sender Mismatch Risk',
        confidence: Math.min(95, Math.max(70, forensics.score)),
        analysis: 'VerifyPulse found a deterministic mismatch between the link, claimed brand, and requested action. Do not use the link; verify through an official app or website you open yourself.',
        findings: forensics.findings,
        whatToDo: ['Do not click, pay, approve a collect request, or share credentials through this message.', 'Open the claimed organisation’s official app or website manually to verify the request.', 'Report suspected financial fraud promptly through 1930.'],
        evidenceSources: ['Local URL and brand forensics'],
        forensics
      }));
    }

    // An obvious local high-confidence scam pattern should not be downgraded to
    // NEEDS_VERIFICATION merely because every external provider is degraded.
    const localRiskPrecheck = assessHighConfidenceFallbackRisk(text);
    if (localRiskPrecheck && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      logScanReliabilityEvent({ requestId, stage: 'local_high_confidence_precheck', provider: 'local_rules', outcome: 'success' });
      return res.status(200).json(safeResult(localRiskPrecheck));
    }

    // Gemini for fact‑checking (news)
    if (checkType === 'news' && GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY, 'news', knowledgeLine);
        if (gemRes) return res.status(200).json(safeResult(gemRes));
      } catch (e) {}
    }
    // ---- Multimodal File Uploads (Images/Audio) ----
    if (fileData && GEMINI_KEY) {
      if (!externalProcessingConsent) {
        return res.status(400).json(safeResult({
          verdict: 'CONSENT_REQUIRED',
          confidence: 100,
          analysis: 'File analysis may send the uploaded file to an external AI provider and therefore requires explicit consent.',
          findings: ['No uploaded file was sent for external processing.'],
          whatToDo: ['Show a clear consent notice in the client and resend only after the user agrees.'],
          evidenceSources: ['Privacy guard']
        }));
      }
      const visionAttempt = await runProviderAttempt({
        requestId,
        stage: 'file_analysis',
        provider: 'gemini',
        operation: () => callGemini(externalAnalysisText, GEMINI_KEY, 'unified', knowledgeLine, fileData)
      });
      if (visionAttempt.ok && visionAttempt.result?.verdict) {
        return res.status(200).json(safeResult(visionAttempt.result));
      }
      return res.status(503).json(safeResult(createServiceUnavailableResult({
        requestId,
        failedProviders: [{ provider: 'gemini', errorCode: visionAttempt.errorCode || 'invalid_provider_verdict' }]
      })));
    }
    // ----- BOUNDED PROVIDER ROUTER -----
    // One primary and independent fallbacks are intentionally used instead of a large fan-out.
    // This reduces latency, makes failures observable, and prevents one request from exhausting many providers.
    const failedProviders = [];
    let providerAttempts = 0;
    // A hard ceiling protects provider quotas; the time budget stops slow chains
    // earlier, while fast failure modes may still reach an independent fallback.
    const MAX_EXTERNAL_PROVIDER_ATTEMPTS = 4;
    const hasUsableVerdict = (result) => {
      const verdict = String(result?.verdict || '').trim().toUpperCase();
      return Boolean(verdict) && !['UNCERTAIN', 'SERVICE_UNAVAILABLE'].includes(verdict);
    };
    const attempt = async ({ stage, provider, operation, capMs = 2200 }) => {
      if (providerAttempts >= MAX_EXTERNAL_PROVIDER_ATTEMPTS) {
        failedProviders.push({ provider, errorCode: 'provider_attempt_limit' });
        logScanReliabilityEvent({ requestId, stage, provider, outcome: 'skipped_budget', errorCode: 'provider_attempt_limit', durationMs: requestBudget.elapsedMs() });
        return null;
      }
      const timeoutMs = requestBudget.timeoutFor({ capMs, minimumMs: 500 });
      if (!timeoutMs) {
        failedProviders.push({ provider, errorCode: 'scan_budget_exhausted' });
        logScanReliabilityEvent({ requestId, stage, provider, outcome: 'skipped_budget', errorCode: 'scan_budget_exhausted', durationMs: requestBudget.elapsedMs() });
        return null;
      }
      providerAttempts += 1;
      const result = await runProviderAttempt({ requestId, stage, provider, operation: () => operation(timeoutMs) });
      if (!result.ok) {
        failedProviders.push({
          provider,
          errorCode: result.errorCode,
          providerStatus: Number.isInteger(result.providerStatus) ? result.providerStatus : null,
          providerReason: typeof result.providerReason === 'string' ? result.providerReason : null,
        });
      }
      if (result.ok && !hasUsableVerdict(result.result)) {
        failedProviders.push({ provider, errorCode: 'invalid_provider_verdict' });
        logScanReliabilityEvent({ requestId, stage, provider, outcome: 'failure', errorCode: 'invalid_provider_verdict' });
        return null;
      }
      return result.ok ? result.result : null;
    };

    // Gemini 2.5 Flash is the primary high-volume route. Groq remains a bounded independent fallback.
    if (GEMINI_KEY) {
      const geminiResult = await attempt({
        stage: 'primary_scan', provider: 'gemini',
        capMs: 2400,
        operation: (timeoutMs) => callGemini(externalAnalysisText, GEMINI_KEY, checkType, knowledgeLine, null, GEMINI_MODEL, timeoutMs)
      });
      if (geminiResult) return res.status(200).json(safeResult(geminiResult));
    } else {
      failedProviders.push({ provider: 'gemini', errorCode: 'provider_not_configured' });
    }

    if (GROQ_KEY) {
      const groqResult = await attempt({
        stage: 'fallback_scan', provider: 'groq',
        capMs: 2200,
        operation: (timeoutMs) => callGroq(GROQ_KEY, externalAnalysisText, checkType, GROQ_MODEL, knowledgeLine, timeoutMs)
      });
      if (groqResult) return res.status(200).json(safeResult(groqResult));
    } else {
      failedProviders.push({ provider: 'groq', errorCode: 'provider_not_configured' });
    }

    if (ANTHROPIC_KEY) {
      const anthropicResult = await attempt({
        stage: 'secondary_fallback_scan', provider: 'anthropic',
        capMs: 2200,
        operation: (timeoutMs) => callAnthropic(ANTHROPIC_KEY, externalAnalysisText, checkType, ANTHROPIC_MODEL, knowledgeLine, timeoutMs)
      });
      if (anthropicResult) return res.status(200).json(safeResult(anthropicResult));
    } else {
      failedProviders.push({ provider: 'anthropic', errorCode: 'provider_not_configured' });
    }

    if (OPENROUTER_KEY) {
      const openRouterResult = await attempt({
        stage: 'secondary_fallback_scan', provider: 'openrouter',
        capMs: 1400,
        operation: (timeoutMs) => callOpenRouter(OPENROUTER_KEY, externalAnalysisText, checkType, knowledgeLine, timeoutMs)
      });
      if (openRouterResult) return res.status(200).json(safeResult(openRouterResult));
    } else {
      failedProviders.push({ provider: 'openrouter', errorCode: 'provider_not_configured' });
    }

    const localRisk = assessHighConfidenceFallbackRisk(text);
    if (localRisk && ['scam', 'phishing', 'gmail', 'url', 'unified'].includes(checkType)) {
      logScanReliabilityEvent({ requestId, stage: 'local_high_confidence_fallback', provider: 'local_rules', outcome: 'success' });
      return res.status(200).json(safeResult(localRisk));
    }

    logScanReliabilityEvent({ requestId, stage: 'scan_router', outcome: 'degraded_verification_response', errorCode: failedProviders.map((entry) => entry.errorCode).join(',') });
    return res.status(200).json(safeResult({
      verdict: 'NEEDS_VERIFICATION',
      scamType: 'Independent Verification Recommended',
      confidence: 0,
      analysis: 'Live model analysis is temporarily unavailable. VerifyPulse did not find a high-confidence local scam signal, but this is not a SAFE result. Please verify the sender, offer, or transaction through an official app or website you open yourself.',
      findings: ['External analysis providers were unavailable or exceeded the request time budget.', 'No high-confidence local rule or reputation match was available for this content.'],
      whatToDo: ['Do not share OTPs, PINs, passwords, payment details, or documents based only on this message.', 'Open the claimed organisation’s official app or website manually to verify the request.', 'Try the scan again later if you still need an AI-assisted assessment.'],
      evidenceSources: ['Service health monitor'],
      serviceStatus: 'degraded',
      failedProviders
    }));
  } catch (error) {
    logScanReliabilityEvent({ requestId, stage: 'handler', outcome: 'degraded_verification_response', errorCode: 'internal_processing_error' });
    return res.status(200).json(safeResult({
      verdict: 'NEEDS_VERIFICATION',
      scamType: 'Independent Verification Recommended',
      confidence: 0,
      analysis: 'VerifyPulse could not complete the live analysis for this request. This is not a SAFE result; verify independently through an official channel.',
      findings: ['An internal analysis step did not complete.'],
      whatToDo: ['Do not act on payment, credential, or verification requests until independently confirmed.', 'Use an official app, manually entered website, or published customer-support channel.', 'Try the scan again later if you need AI-assisted analysis.'],
      evidenceSources: ['Service health monitor'],
      serviceStatus: 'degraded',
      failedProviders: [{ provider: 'verify_handler', errorCode: 'internal_processing_error' }]
    }));
  }
}

async function getRecentScamUrls() {
  if (Date.now() < threatFeedCache.expiresAt) return threatFeedCache.values;
  try {
    const pipelineURL = 'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/latest_scams.json';
    const allURLs = await fetchJsonWithTimeout(pipelineURL, {}, { provider: 'threat_feed', timeoutMs: 1200 });
    threatFeedCache.values = Array.isArray(allURLs) ? allURLs.slice(-20) : [];
    threatFeedCache.expiresAt = Date.now() + 60_000;
  } catch {
    // A stale or unavailable enrichment feed must never create a SAFE verdict.
    threatFeedCache.expiresAt = Date.now() + 15_000;
  }
  return threatFeedCache.values;
}

// ========== Helper functions ==========
async function checkWithSafeBrowsing(inputUrl, apiKey, timeoutMs = 650) {
  try {
    const payload = {
      client: { clientId: "verifypulse", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"],
        threatEntries: [{ url: inputUrl }]
      }
    };
    const data = await fetchJsonWithTimeout(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST', body: JSON.stringify(payload)
    }, { provider: 'google_safe_browsing', timeoutMs });
    if (data.matches) {
      return {
        found: true,
        verdict: 'DANGEROUS',
        confidence: 100,
        analysis: 'Known malicious link detected by Google Safe Browsing.',
        findings: [],
        evidenceSources: ['Google Safe Browsing']
      };
    }
    return { found: false, checked: true };
  } catch (e) { return { found: false, checked: false }; }
}
async function checkWithWebRisk(inputUrl, apiKey, timeoutMs = 800) {
  try {
    const query = new URLSearchParams();
    query.append('threatTypes', 'MALWARE');
    query.append('threatTypes', 'SOCIAL_ENGINEERING');
    query.append('uri', inputUrl);
    query.append('key', apiKey);
    const data = await fetchJsonWithTimeout(`https://webrisk.googleapis.com/v1/uris:search?${query.toString()}`, {
      method: 'GET'
    }, { provider: 'google_web_risk', timeoutMs });
    if (Array.isArray(data.threat?.threatTypes) && data.threat.threatTypes.length > 0) {
      return {
        found: true,
        verdict: 'DANGEROUS',
        confidence: 100,
        analysis: 'Known malicious link detected by Google Web Risk.',
        findings: [`Google Web Risk matched: ${data.threat.threatTypes.join(', ')}.`],
        evidenceSources: ['Google Web Risk']
      };
    }
    return { found: false, checked: true };
  } catch {
    return { found: false, checked: false };
  }
}

async function callGemini(text, apiKey, type = 'news', knowledgeLine = '', fileData = null, model = process.env.GEMINI_MODEL || 'gemini-2.5-flash', timeoutMs = 1050) {
  const systemPrompt = getPrompt(type, knowledgeLine) + " You must return valid JSON.";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${apiKey}`;
  
  let parts = [{ text: `${systemPrompt}\n\nInput: "${text}"` }];
  if (fileData && fileData.base64 && fileData.mimeType) {
    parts.push({ inlineData: { mimeType: fileData.mimeType, data: fileData.base64 } });
  }
  const body = { contents: [{ parts }] };
  const data = await fetchJsonWithTimeout(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, { provider: 'gemini', timeoutMs });
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!content) throw new Error('Empty Gemini response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  if (parsed.confidence > 0 && parsed.confidence <= 1) parsed.confidence = Math.round(parsed.confidence * 100);
  return parsed;
}
async function callGroq(apiKey, text, type, model, knowledgeLine = '', timeoutMs = 1050) {
  const systemPrompt = getPrompt(type, knowledgeLine);
  const url = 'https://api.groq.com/openai/v1/chat/completions';
  const data = await fetchJsonWithTimeout(url, {
    method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model, messages: [
        { role: 'system', content: "You are a cybersecurity and scam‑detection AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings, whatToDo." },
        { role: 'user', content: systemPrompt + `\n\nInput: "${text}"` }
      ], temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
    })
  }, { provider: 'groq', timeoutMs });
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('Empty Groq response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  if (parsed.confidence > 0 && parsed.confidence <= 1) parsed.confidence = Math.round(parsed.confidence * 100);
  // enrich scamType if missing
  if (!parsed.scamType) {
    const lower = (parsed.verdict + ' ' + (parsed.analysis||'')).toLowerCase();
    if (lower.includes('phish')) parsed.scamType = 'Phishing Attack';
    else if (lower.includes('fake reward') || lower.includes('lottery')) parsed.scamType = 'Fake Reward Scam';
    else if (lower.includes('otp')) parsed.scamType = 'OTP Fraud';
    else if (lower.includes('upi')) parsed.scamType = 'UPI Fraud';
    else if (lower.includes('job')) parsed.scamType = 'Job Scam';
    else if (lower.includes('loan')) parsed.scamType = 'Loan Fraud';
    else if (lower.includes('bank') || lower.includes('kyc')) parsed.scamType = 'Bank Impersonation';
    else if (parsed.verdict === 'SAFE') parsed.scamType = 'Safe Content';
    else if (parsed.verdict === 'SUSPICIOUS') parsed.scamType = 'Suspicious Activity';
    else if (parsed.verdict === 'DANGEROUS') parsed.scamType = 'Dangerous Threat';
    else parsed.scamType = 'Potential Scam';
  }
  if (!parsed.whatToDo) {
    const tips = [];
    if (parsed.scamType === 'Phishing Attack' || parsed.scamType === 'Bank Impersonation') {
      tips.push('Do NOT click the link', 'Do NOT enter login details', 'Open official website manually');
    } else if (parsed.scamType === 'Fake Reward Scam') {
      tips.push('Do NOT send any money', 'Do NOT share personal info', 'Report the sender');
    } else if (parsed.scamType === 'OTP Fraud') {
      tips.push('Never share OTP', 'No legit company asks OTP', 'Block and report');
    } else if (parsed.scamType === 'UPI Fraud') {
      tips.push('Do NOT approve payment', 'Check receiver name', 'Report in UPI app');
    } else {
      tips.push('Be cautious with unsolicited messages', 'Do not share sensitive info', 'Verify via official channels');
    }
    parsed.whatToDo = tips;
  }
  return parsed;
}
async function callAnthropic(apiKey, text, type, model, knowledgeLine = '', timeoutMs = 1050) {
  const data = await fetchJsonWithTimeout('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model,
      max_tokens: 450,
      temperature: 0.1,
      system: 'You are a cybersecurity scam detector. Return only valid JSON with verdict, scamType, confidence, analysis, findings, and whatToDo.',
      messages: [{ role: 'user', content: `${getPrompt(type, knowledgeLine)}\n\nInput: "${text}"` }]
    })
  }, { provider: 'anthropic', timeoutMs });
  const content = data.content?.find((block) => block?.type === 'text')?.text;
  if (!content) throw new Error('Empty Anthropic response');
  try { return JSON.parse(content); } catch {
    const match = content.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
    throw new Error('Invalid Anthropic JSON');
  }
}

async function callOpenRouter(apiKey, text, type, knowledgeLine = '', timeoutMs = 1050) {
  const prompt = `${getPrompt(type, knowledgeLine)}\n\nInput: "${text}"`;
  const data = await fetchJsonWithTimeout('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({
      // The free router selects an available no-cost model; it remains a limited fallback, not a primary capacity guarantee.
      model: 'openrouter/free',
      messages: [
        { role: 'system', content: 'You are a cybersecurity scam detector. Return only valid JSON with verdict, scamType, confidence, analysis, findings, and whatToDo.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.1,
      max_tokens: 450
    })
  }, { provider: 'openrouter', timeoutMs });
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('Empty OpenRouter response');
  try { return JSON.parse(content); } catch {
    const match = content.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
    throw new Error('Invalid OpenRouter JSON');
  }
}

function assessHighConfidenceFallbackRisk(msg) {
  const value = String(msg || '');
  // SMS messages frequently omit the scheme (for example, bit.ly/path), so the
  // local classifier recognises both full and bare web addresses.
  const hasUrl = /\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/i.test(value)
    || /\b(?:https?:\/\/)?[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:\/[^\s]*)?/i.test(value);
  const shortenedOrObscuredUrl = /\b(?:https?:\/\/)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|[0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\/|\b)/i.test(value);
  const apkDownload = /\b(?:download|install|update)\b[^\n]{0,80}\.(?:apk|exe|msi)\b|\.(?:apk|exe|msi)\b[^\n]{0,80}\b(?:download|install|update)\b/i.test(value);
  const sensitiveRequest = /\b(?:otp|pin|cvv|password|card details?|bank account details?|screen share|remote access|aadhaar|kyc)\b/i.test(value);
  const paymentRequest = /(?:₹|\brs\.?\s*\d|\binr\s*\d|upi|collect request|processing fee|verification fee|pay now|payment|फीस|शुल्क|पैसे|फीजु|చెల్లించ|డబ్బు)/i.test(value);
  const pressure = /\b(?:within|minutes?|hours?|immediately|urgent|freeze|blocked|suspend|arrest|fir|penalty|last chance)\b|तुरंत|आज|వెంటనే/i.test(value);
  const authority = /\b(?:rbi|reserve bank|income tax|cbi|cyber crime|police|trai|customs|court|government|bank)\b/i.test(value);
  const untrustedContact = /\b(?:whatsapp|telegram|reply\s+(?:yes|ok)|verification call|video call|call now)\b|व्हाट्सअॅप|వాట్సాప్/i.test(value);
  const rewardClaim = /\b(?:lottery|prize|reward|cashback|gift)\b|लॉटरी|इनाम|బహుమతి|లాటరీ/i.test(value);
  // Narrow local safeguard: a high-value prize/lottery promise combined with a
  // direction to claim through an unverified link is a common social-engineering pattern.
  // It deliberately does not classify ordinary rewards or legitimate announcements by keyword alone.
  const highValueReward = /\b(?:\d+(?:[.,]\d+)?\s*)?(?:crore|lakh)\b|₹\s*\d{4,}|\b(?:million|billion)\b/i.test(value);
  const claimLinkAction = /\b(?:click|tap|open|visit|claim|redeem)\b[^\n]{0,60}\b(?:link|here|below)\b|\b(?:link|below)\b[^\n]{0,60}\b(?:claim|redeem)\b|\b(?:click|tap|open|visit|claim|redeem)\b[^\n]{0,60}\bhttps?:\/\//i.test(value);
  const prizeClaimLinkBait = rewardClaim && highValueReward && claimLinkAction;
  // A real bank may send routine account notices, but a named-bank message that
  // threatens account blocking and demands a verification/processing fee is a
  // sufficiently specific social-engineering pattern to protect locally.
  const namedBank = /\b(?:sbi|state bank(?: of india)?|hdfc|icici|axis|kotak|pnb|punjab national bank|canara|bank of baroda|indian bank|union bank)\b/i.test(value);
  const accountBlockingFeeTrap = /\b(?:account|a\/?c)\b/i.test(value)
    && /\b(?:freeze|frozen|blocked|block|suspend|suspended)\b/i.test(value)
    && /\b(?:verification fee|processing fee)\b/i.test(value);
  const highRisk = (apkDownload && (pressure || untrustedContact || paymentRequest || sensitiveRequest))
    || (hasUrl && shortenedOrObscuredUrl && (sensitiveRequest || paymentRequest || (authority && pressure)))
    || (authority && pressure && paymentRequest && (sensitiveRequest || untrustedContact))
    || (rewardClaim && paymentRequest && untrustedContact)
    || prizeClaimLinkBait
    || (namedBank && accountBlockingFeeTrap);
  if (!highRisk) return null;
  const findings = [];
  if (apkDownload) findings.push('The message pressures you to download or install an executable application file.');
  if (shortenedOrObscuredUrl) findings.push('The message uses a shortened, obscured, or direct-IP link.');
  if (sensitiveRequest) findings.push('The message requests sensitive credentials, identity information, screen sharing, or KYC action.');
  if (paymentRequest) findings.push('The message asks for payment, a collect request, or a verification fee.');
  if (authority && pressure) findings.push('The message combines an authority claim with urgent pressure.');
  if (namedBank && accountBlockingFeeTrap) findings.push('A named bank is used with an account-blocking threat and a verification or processing fee demand.');
  if (rewardClaim && paymentRequest && untrustedContact) findings.push('The message combines a reward claim, payment request, and an untrusted contact channel.');
  if (prizeClaimLinkBait) findings.push('A high-value prize or lottery promise directs you to claim it through an unverified link.');
  return {
    verdict: 'SUSPICIOUS',
    scamType: prizeClaimLinkBait ? 'Prize Claim Social Engineering Risk' : 'High-Confidence Social Engineering Risk',
    confidence: prizeClaimLinkBait ? 92 : 88,
    analysis: 'External model analysis is temporarily unavailable, but local high-confidence scam signals were detected. Treat this content as risky and verify independently.',
    findings,
    whatToDo: ['Do not click links, install files, pay, or share OTPs, PINs, passwords, or personal documents.', 'Contact the claimed organisation through an official website or helpline you find yourself.', 'Report suspected financial fraud quickly through 1930.'],
    evidenceSources: ['Local high-confidence fallback rules']
  };
}

function getPrompt(type, knowledgeLine = '') {
  const baseSCAM = `You are an Indian scam detection expert. Analyze the message and return JSON with:
- verdict: SCAM / FRAUD / SAFE / SUSPICIOUS
- scamType: one of [Phishing Attack, Fake Reward Scam, OTP Fraud, UPI Fraud, Job Scam, Loan Fraud, Bank Impersonation, Safe Content]
- confidence: 65-99
- analysis: 2-3 sentences
- findings: array of bullet-point red flags
- whatToDo: array of actionable steps.
Practical risk-analysis guidelines (do not present these as legal advice or proof that a message is legitimate):
1. Indian Banks (SBI, HDFC, ICICI, etc.) NEVER send bit.ly, tinyurl, or random IP address links for KYC. Real KYC is done inside official apps (YONO, iMobile) or official .co.in / .com domains.
2. Official Entities NEVER ask you to download an .apk file over WhatsApp.
3. Police, CBI, Telecom (TRAI), and Customs NEVER call threatening to arrest you unless you pay via UPI or Crypto. 
4. Income Tax Dept NEVER asks for PIN, CVV, or passwords via SMS.
5. Legitimate companies DO NOT ask you to "Pay Rs 10" to receive a courier package or a gift.
CRITICAL RULES FOR PREVENTING FALSE POSITIVES (OBEY STRICTLY):
1. Distinguish Real vs Fake KYC: An official message reminding you to "Visit your branch or use the official YONO app for KYC" is SAFE. A message saying "Your account is blocked, click this random link to update KYC" is a SCAM.
2. Official Government alerts (e.g., IMD Heat Wave warnings, disaster management, health advisories) are ALWAYS SAFE.
3. Official notifications from verified brands (e.g., Zerodha trades, Bank balance updates) that do NOT ask for sensitive info/money via shady links are SAFE.
4. Do NOT flag a message as a scam just because it uses "urgent" language if it is a public service announcement or legitimate weather/stock alert.
Examples of SCAMS: fake KBC lottery, SBI KYC via bit.ly link, "Digital Arrest" calls, FedEx courier scam, job fraud with advance payment.
Examples of SAFE: Environmental heat wave alert from Govt, Zerodha trade confirmation, official SBI SMS telling you to use the YONO app.`;
  if (type === 'news') return `Determine if news is TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply JSON.${knowledgeLine}`;
  if (type === 'url') return `Analyze URL for safety. Return JSON.${knowledgeLine}`;
  if (type === 'phishing') return baseSCAM + knowledgeLine;
  if (type === 'scam') return baseSCAM + knowledgeLine;
  if (type === 'unified') return baseSCAM + knowledgeLine;
  if (type === 'phone') return `Analyze phone number (spam/fraud/safe). Return JSON.${knowledgeLine}`;
  if (type === 'upi') return `Analyze UPI ID for fraud. Return JSON.${knowledgeLine}`;
  if (type === 'gmail') return baseSCAM + knowledgeLine;
  return `Analyze and return JSON with verdict, confidence, analysis, findings.`;
}
