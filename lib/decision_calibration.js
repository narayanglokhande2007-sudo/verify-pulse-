// lib/decision_calibration.js
// Versioned, deterministic interpretation of a VerifyPulse decision.
// Confidence remains an input-specific score, not a probability or guarantee.

const EVIDENCE_BACKED_SOURCES = new Set([
  'Trusted domain registry',
  'Local social-engineering rules',
  'Local high-confidence fallback rules',
  'Local notification ambiguity rules',
  'Local sender-authentication policy',
  'Local URL and brand forensics',
  'Local multilingual intent forensics',
  'Source-aware threat intelligence'
]);

export function calibrateDecision({ verdict, confidence, evidenceSources = [] } = {}) {
  const normalizedVerdict = String(verdict || 'NEEDS_VERIFICATION').toUpperCase();
  const sources = Array.isArray(evidenceSources) ? evidenceSources.filter(Boolean) : [];
  const serviceDegraded = sources.includes('Service health monitor');
  const positiveGoogleReputationMatch = normalizedVerdict === 'DANGEROUS'
    && (sources.includes('Google Safe Browsing') || sources.includes('Google Web Risk'));
  const evidenceBacked = positiveGoogleReputationMatch || sources.some((source) => EVIDENCE_BACKED_SOURCES.has(source));
  const boundedConfidence = Number.isFinite(Number(confidence))
    ? Math.max(0, Math.min(100, Number(confidence)))
    : null;

  const riskBand = {
    DANGEROUS: 'critical-risk',
    SUSPICIOUS: 'high-risk',
    NEEDS_VERIFICATION: 'verification-required',
    CAUTION: 'privacy-caution',
    CONSENT_REQUIRED: 'consent-required',
    SERVICE_UNAVAILABLE: 'service-unavailable',
    SAFE: 'lower-risk'
  }[normalizedVerdict] || 'verification-required';

  const decisionBasis = serviceDegraded
    ? 'service-status'
    : evidenceBacked
      ? 'evidence-backed'
      : 'model-assisted';

  return {
    policyVersion: 'vp-calibration-1',
    riskBand,
    decisionBasis,
    modelConfidence: boundedConfidence,
    confidenceInterpretation: 'Confidence is an input-specific ranking signal, not proof that a sender, transaction, website, or message is authentic.',
    safeIsNotAuthentication: normalizedVerdict === 'SAFE',
    independentVerificationRecommended: ['DANGEROUS', 'SUSPICIOUS', 'NEEDS_VERIFICATION', 'CAUTION', 'CONSENT_REQUIRED', 'SERVICE_UNAVAILABLE'].includes(normalizedVerdict)
  };
}
