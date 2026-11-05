// lib/dispute_registry.js
// VerifyPulse Dispute Resolution & Calibrated Domain Registry
// Tracks reviewed domains under formal dispute tickets to prevent model false positives.

import { canonicalizeUrl, extractUrlCandidates } from './url_forensics.js';

export const DISPUTE_CALIBRATED_REGISTRY = {
  'mycontent.academy': {
    ticketId: 'VP-REP-2026-1104',
    calibratedAt: '2026-11-05',
    verdict: 'NEEDS_VERIFICATION',
    scamType: 'Unverified Domain / Review Calibrated',
    confidence: 0,
    analysis: 'This domain was formally reviewed under VerifyPulse dispute ticket VP-REP-2026-1104. No active malware, credential harvesting, or threat distribution listing was found in global threat feeds, but service availability and ownership authentication remain required before treating it as verified.',
    findings: [
      'No active threat listing found on Google Safe Browsing or multi-source threat intelligence.',
      'Phishing classification removed; calibrated to NEEDS_VERIFICATION under ticket VP-REP-2026-1104.',
      'Unverified root domain; direct service authentication required for full trust rating.'
    ],
    whatToDo: [
      'Do not share passwords, financial data, or sensitive credentials until service identity is independently verified.',
      'Access services only through published and verified organizational communication channels.'
    ]
  },
  'mycontent.agency': {
    ticketId: 'VP-REP-2026-1104',
    calibratedAt: '2026-11-05',
    verdict: 'NEEDS_VERIFICATION',
    scamType: 'Unverified Domain / Review Calibrated',
    confidence: 0,
    analysis: 'This domain was formally reviewed under VerifyPulse dispute ticket VP-REP-2026-1104. No active malware, credential harvesting, or threat distribution listing was found in global threat feeds, but service availability and ownership authentication remain required before treating it as verified.',
    findings: [
      'No active threat listing found on Google Safe Browsing or multi-source threat intelligence.',
      'Phishing classification removed; calibrated to NEEDS_VERIFICATION under ticket VP-REP-2026-1104.',
      'Unverified root domain; direct service authentication required for full trust rating.'
    ],
    whatToDo: [
      'Do not share passwords, financial data, or sensitive credentials until service identity is independently verified.',
      'Access services only through published and verified organizational communication channels.'
    ]
  }
};

export function assessDisputeCalibratedDomains(text) {
  const candidates = extractUrlCandidates(text);
  if (!candidates || candidates.length === 0) return null;

  for (const candidate of candidates) {
    const parsed = canonicalizeUrl(candidate);
    if (!parsed || !parsed.hostname) continue;

    const host = parsed.hostname.toLowerCase();
    for (const [calibratedHost, entry] of Object.entries(DISPUTE_CALIBRATED_REGISTRY)) {
      if (host === calibratedHost || host.endsWith('.' + calibratedHost)) {
        return {
          verdict: entry.verdict,
          scamType: entry.scamType,
          confidence: entry.confidence,
          analysis: entry.analysis,
          findings: [...entry.findings],
          whatToDo: [...entry.whatToDo],
          evidenceSources: ['Domain dispute resolution registry'],
          disputeMetadata: {
            ticketId: entry.ticketId,
            hostname: calibratedHost,
            calibratedAt: entry.calibratedAt
          }
        };
      }
    }
  }
  return null;
}
