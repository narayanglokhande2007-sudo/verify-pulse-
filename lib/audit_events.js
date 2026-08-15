// lib/audit_events.js
// Privacy-safe, structured operational events for platform logs.
// Never include raw scan text, URLs, API keys, IP addresses, contact data, or credentials.

const SAFE_EVENT_TYPES = new Set([
  'b2b_authentication',
  'b2b_authorization',
  'b2b_scan_completed',
  'b2b_scan_failed'
]);

function optionalIdentifier(value, maxLength = 96) {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().replace(/[^a-zA-Z0-9._:-]/g, '').slice(0, maxLength);
  return normalized || undefined;
}

export function emitB2bAuditEvent({
  type,
  correlationId,
  tenantId,
  keyId,
  outcome,
  statusCode,
  scope,
  errorCode
} = {}) {
  const event = {
    event: 'verifypulse.b2b_audit',
    schemaVersion: 'vp-b2b-audit-1',
    recordedAt: new Date().toISOString(),
    type: SAFE_EVENT_TYPES.has(type) ? type : 'b2b_authorization',
    correlationId: optionalIdentifier(correlationId, 128),
    tenantId: optionalIdentifier(tenantId),
    keyId: optionalIdentifier(keyId),
    outcome: optionalIdentifier(outcome, 40) || 'unknown',
    statusCode: Number.isInteger(statusCode) ? statusCode : undefined,
    scope: optionalIdentifier(scope, 80),
    errorCode: optionalIdentifier(errorCode, 80),
    dataHandling: 'Metadata only; raw scan content, URLs, API keys, IP addresses, contact details, credentials, and personal identifiers are excluded.'
  };
  console.info(JSON.stringify(event));
  return event;
}
