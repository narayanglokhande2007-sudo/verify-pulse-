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

const tenantTelemetryStore = new Map();
const TELEMETRY_REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TELEMETRY_REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const TELEMETRY_NATIVE_REDIS_URL = process.env.VERIFYPULSE_REDIS_URL || process.env.REDIS_URL;
let telemetryNativeClientPromise = null;

async function getTelemetryNativeClient() {
  if (!TELEMETRY_NATIVE_REDIS_URL) return null;
  if (!telemetryNativeClientPromise) {
    telemetryNativeClientPromise = (async () => {
      try {
        const redisPkg = await import('redis');
        const createClient = redisPkg.createClient || redisPkg.default?.createClient;
        if (!createClient) return null;
        const client = createClient({ url: TELEMETRY_NATIVE_REDIS_URL });
        client.on('error', (error) => console.error('VerifyPulse telemetry native Redis Error:', error.message));
        await client.connect();
        return client;
      } catch (error) {
        console.error('VerifyPulse telemetry native Redis Error:', error.message);
        telemetryNativeClientPromise = null;
        return null;
      }
    })();
  }
  return telemetryNativeClientPromise;
}

async function telemetryRedisCommand(command, ...args) {
  if (TELEMETRY_NATIVE_REDIS_URL) {
    try {
      const client = await getTelemetryNativeClient();
      if (client) {
        return await client.sendCommand([command, ...args.map(String)]);
      }
    } catch (error) {
      console.error('VerifyPulse telemetry native Redis Error:', error.message);
      telemetryNativeClientPromise = null;
    }
  }
  if (!TELEMETRY_REDIS_URL || !TELEMETRY_REDIS_TOKEN) return null;
  try {
    const response = await fetch(TELEMETRY_REDIS_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${TELEMETRY_REDIS_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([command, ...args])
    });
    const data = await response.json();
    if (!response.ok || data.error) throw new Error(data.error || `HTTP ${response.status}`);
    return data.result;
  } catch (error) {
    console.error('VerifyPulse telemetry persistence error:', error.message);
    return null;
  }
}

function telemetryKey(tenantId) {
  const safeTenantId = optionalIdentifier(String(tenantId), 96);
  return safeTenantId ? `verifypulse:tenant-telemetry:${safeTenantId}` : null;
}

async function persistTenantTelemetry(tenantId, { isThreat = false, valueSaved = 15000 } = {}) {
  const key = telemetryKey(tenantId);
  if (!key) return;
  await telemetryRedisCommand('HINCRBY', key, 'totalScans', 1);
  if (isThreat) {
    await telemetryRedisCommand('HINCRBY', key, 'fraudsBlocked', 1);
    await telemetryRedisCommand('HINCRBYFLOAT', key, 'totalValueSaved', Number(valueSaved) || 0);
  }
  await telemetryRedisCommand('EXPIRE', key, 31536000);
}

export function recordTenantScanTelemetry(tenantId, { isThreat = false, valueSaved = 15000 } = {}) {
  if (!tenantId) return;
  const existing = tenantTelemetryStore.get(tenantId) || { totalScans: 0, fraudsBlocked: 0, totalValueSaved: 0 };
  existing.totalScans += 1;
  if (isThreat) {
    existing.fraudsBlocked += 1;
    existing.totalValueSaved += valueSaved;
  }
  tenantTelemetryStore.set(tenantId, existing);
  // Persistence is best-effort and never blocks or changes the scan result.
  void persistTenantTelemetry(tenantId, { isThreat, valueSaved });
}

export function getTenantAuditTelemetry(tenantId) {
  if (!tenantId) return { totalScans: 0, fraudsBlocked: 0, totalValueSaved: 0 };
  return tenantTelemetryStore.get(tenantId) || { totalScans: 0, fraudsBlocked: 0, totalValueSaved: 0 };
}

export async function getTenantAuditTelemetryPersistent(tenantId) {
  const local = getTenantAuditTelemetry(tenantId);
  const key = telemetryKey(tenantId);
  if (!key || (!TELEMETRY_NATIVE_REDIS_URL && (!TELEMETRY_REDIS_URL || !TELEMETRY_REDIS_TOKEN))) return local;
  const result = await telemetryRedisCommand('HGETALL', key);
  const values = Array.isArray(result)
    ? Object.fromEntries(Array.from({ length: result.length - (result.length % 2) }, (_, index) => [result[index * 2], result[index * 2 + 1]]))
    : (result && typeof result === 'object' ? result : {});
  return {
    totalScans: Math.max(local.totalScans, Number(values.totalScans || 0)),
    fraudsBlocked: Math.max(local.fraudsBlocked, Number(values.fraudsBlocked || 0)),
    totalValueSaved: Math.max(local.totalValueSaved, Number(values.totalValueSaved || 0))
  };
}

export function emitB2bAuditEvent({
  type,
  correlationId,
  tenantId,
  keyId,
  outcome,
  statusCode,
  scope,
  errorCode,
  isThreat
} = {}) {
  if (tenantId && (type === 'b2b_scan_completed' || isThreat)) {
    recordTenantScanTelemetry(tenantId, { isThreat: Boolean(isThreat || outcome === 'threat_blocked') });
  }

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
