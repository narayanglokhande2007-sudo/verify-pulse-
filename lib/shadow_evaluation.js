// lib/shadow_evaluation.js
// Non-blocking decision-quality telemetry. It receives only local derived signals;
// it never stores or exports raw user text, credentials, contact data, or URLs.

const RISK_VERDICTS = new Set(['DANGEROUS', 'SUSPICIOUS']);

export function createShadowEvaluation({ verdict, evidenceSources = [], intentForensics, urlForensics } = {}) {
  const servedVerdict = String(verdict || 'NEEDS_VERIFICATION').toUpperCase();
  const deterministicRisk = Boolean(intentForensics?.highRisk || urlForensics?.highRisk);
  const servedRisk = RISK_VERDICTS.has(servedVerdict);
  const serviceDegraded = Array.isArray(evidenceSources) && evidenceSources.includes('Service health monitor');
  const candidateVerdict = deterministicRisk ? 'SUSPICIOUS' : 'NO_LOCAL_OVERRIDE';
  const agreement = deterministicRisk ? servedRisk : servedVerdict !== 'SAFE' || !serviceDegraded;

  return {
    schemaVersion: 'vp-shadow-eval-1',
    mode: 'non-blocking',
    servedVerdict,
    candidateVerdict,
    agreement,
    serviceDegraded,
    localSignals: {
      intentSignalIds: Array.isArray(intentForensics?.signals) ? intentForensics.signals.slice(0, 6) : [],
      urlSignalIds: Array.isArray(urlForensics?.urls)
        ? urlForensics.urls.flatMap((entry) => Array.isArray(entry.signals) ? entry.signals : []).slice(0, 6)
        : []
    },
    dataHandling: 'Derived local signal identifiers only; no raw scanned content, URL, contact detail, credential, or personal identifier is retained.'
  };
}
