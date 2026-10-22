import crypto from 'crypto';

// Best-effort in-memory limiter for a single serverless instance. It provides
// immediate abuse protection but must be replaced or supplemented by a shared
// store (for example, Redis/KV) when the deployment scales across instances.
const rateLimitStore = globalThis.__verifyPulseRateLimitStore || new Map();
globalThis.__verifyPulseRateLimitStore = rateLimitStore;
let warnedServerlessStandalone = false;

const B2B_SCAN_SCOPE = 'b2b:scan';

function getPositiveInteger(value, fallback, maximum) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, maximum);
}

export function getClientIp(req) {
  const vercelForwardedFor = req.headers?.['x-vercel-forwarded-for'];
  const cfConnectingIp = req.headers?.['cf-connecting-ip'];
  const realIp = req.headers?.['x-real-ip'];
  const forwardedFor = req.headers?.['x-forwarded-for'];
  const raw = vercelForwardedFor || cfConnectingIp || realIp || forwardedFor || req.socket?.remoteAddress || 'unknown';
  const candidate = String(Array.isArray(raw) ? raw[0] : raw).split(',')[0].trim();
  const sanitized = candidate.replace(/^::ffff:/i, '').replace(/[^a-f0-9:.]/gi, '').slice(0, 64);
  return sanitized || 'unknown';
}

export function enforceRateLimit(req, {
  scope,
  limit = 20,
  windowMs = 60_000,
} = {}) {
  if (!scope) throw new Error('A rate-limit scope is required.');

  const now = Date.now();
  const key = `${scope}:${getClientIp(req)}`;
  const current = rateLimitStore.get(key);
  const activeWindow = current && now < current.resetAt
    ? current
    : { count: 0, resetAt: now + windowMs };

  activeWindow.count += 1;
  rateLimitStore.set(key, activeWindow);

  // Opportunistic cleanup keeps the memory footprint bounded without an extra job.
  if (rateLimitStore.size > 2_000) {
    for (const [entryKey, entry] of rateLimitStore.entries()) {
      if (entry.resetAt <= now) rateLimitStore.delete(entryKey);
    }
  }

  // Warn once in production if deployed across multi-instance serverless without distributed store
  if (!warnedServerlessStandalone && process.env.VERCEL && !process.env.KV_REST_API_URL && !process.env.UPSTASH_REDIS_REST_URL && !process.env.VERIFYPULSE_REDIS_URL && !process.env.REDIS_URL) {
    warnedServerlessStandalone = true;
    console.warn('[SECURITY] Rate limiter running in standalone memory mode. Configure KV_REST_API_URL or REDIS_URL for distributed multi-instance protection.');
  }

  const retryAfterSeconds = Math.max(1, Math.ceil((activeWindow.resetAt - now) / 1000));
  return {
    allowed: activeWindow.count <= limit,
    remaining: Math.max(0, limit - activeWindow.count),
    limit,
    retryAfterSeconds,
    resetAt: activeWindow.resetAt,
  };
}

// Async distributed rate limiter using Redis / Vercel KV for multi-container deployments
export async function enforceDistributedRateLimit(req, {
  scope,
  limit = 20,
  windowMs = 60_000,
} = {}) {
  const localResult = enforceRateLimit(req, { scope, limit, windowMs });
  if (!localResult.allowed) return localResult;

  const clientIp = getClientIp(req);
  const redisKey = `ratelimit:${scope}:${clientIp}`;
  const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));

  // 1. Native Redis
  const nativeUrl = process.env.VERIFYPULSE_REDIS_URL || process.env.REDIS_URL;
  if (nativeUrl) {
    try {
      const redisPkg = await import('redis');
      const createClient = redisPkg.createClient || redisPkg.default?.createClient;
      if (createClient) {
        const client = createClient({ url: nativeUrl, socket: { connectTimeout: 1200 } });
        client.on('error', () => {});
        await client.connect();
        const currentCount = await client.incr(redisKey);
        if (currentCount === 1) {
          await client.expire(redisKey, ttlSeconds);
        }
        const ttl = await client.ttl(redisKey);
        await client.disconnect();
        return {
          allowed: currentCount <= limit,
          remaining: Math.max(0, limit - currentCount),
          limit,
          retryAfterSeconds: Math.max(1, ttl),
          resetAt: Date.now() + Math.max(1, ttl) * 1000,
          distributed: true,
        };
      }
    } catch {
      // Fallback gracefully
    }
  }

  // 2. Upstash / Vercel KV REST
  const restUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const restToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (restUrl && restToken) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1200);
      const res = await fetch(restUrl, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${restToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(['INCR', redisKey]),
      });
      clearTimeout(timeoutId);
      const data = await res.json();
      const currentCount = Number(data?.result || 1);
      if (currentCount === 1) {
        const expController = new AbortController();
        const expTimeoutId = setTimeout(() => expController.abort(), 800);
        await fetch(restUrl, {
          method: 'POST',
          signal: expController.signal,
          headers: {
            Authorization: `Bearer ${restToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(['EXPIRE', redisKey, String(ttlSeconds)]),
        }).catch(() => {});
        clearTimeout(expTimeoutId);
      }
      return {
        allowed: currentCount <= limit,
        remaining: Math.max(0, limit - currentCount),
        limit,
        retryAfterSeconds: ttlSeconds,
        resetAt: Date.now() + windowMs,
        distributed: true,
      };
    } catch {
      // Fallback gracefully
    }
  }

  return localResult;
}

export function setRateLimitHeaders(res, result) {
  res.setHeader('RateLimit-Limit', String(result.limit));
  res.setHeader('RateLimit-Remaining', String(result.remaining));
  res.setHeader('RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));
  if (!result.allowed) res.setHeader('Retry-After', String(result.retryAfterSeconds));
}

function keyDigest(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function timingSafeHashMatch(candidate, expected) {
  const candidateBuffer = Buffer.from(candidate, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  return candidateBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(candidateBuffer, expectedBuffer);
}

function configuredKeyDigests() {
  return String(process.env.VERIFYPULSE_B2B_API_KEY_HASHES || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter((value) => /^[a-f0-9]{64}$/.test(value));
}

function safeIdentifier(value, maximum = 96) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return /^[A-Za-z0-9._:-]{1,96}$/.test(normalized) ? normalized.slice(0, maximum) : null;
}

function normalizeScopes(value) {
  const values = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : [];
  const scopes = [...new Set(values.map((item) => String(item).trim()).filter((item) => /^[a-z0-9:*._-]{1,80}$/i.test(item)))];
  return scopes;
}

function configuredKeyRegistry() {
  const raw = String(process.env.VERIFYPULSE_B2B_KEY_REGISTRY || '').trim();
  if (!raw) return { configured: false, valid: true, entries: [] };
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 500) return { configured: true, valid: false, entries: [] };
    const entries = [];
    const ids = new Set();
    for (const item of parsed) {
      const keyId = safeIdentifier(item?.keyId);
      const tenantId = safeIdentifier(item?.tenantId);
      const keyHash = typeof item?.sha256 === 'string' ? item.sha256.toLowerCase() : '';
      const scopes = normalizeScopes(item?.scopes);
      const expiresAt = Date.parse(String(item?.expiresAt || ''));
      if (!keyId || !tenantId || !/^[a-f0-9]{64}$/.test(keyHash) || scopes.length === 0 || !Number.isFinite(expiresAt) || ids.has(keyId)) {
        return { configured: true, valid: false, entries: [] };
      }
      ids.add(keyId);
      const tier = [1, 2, 3].includes(Number(item?.tier)) ? Number(item.tier) : 1;
      entries.push({
        keyId,
        tenantId,
        tier,
        sha256: keyHash,
        scopes,
        expiresAt,
        status: item?.status === 'revoked' ? 'revoked' : 'active'
      });
    }
    return { configured: true, valid: true, entries };
  } catch {
    return { configured: true, valid: false, entries: [] };
  }
}

function suppliedApiKey(req) {
  const headerValue = req.headers?.['x-api-key'] || req.headers?.authorization?.replace(/^Bearer\s+/i, '');
  return typeof headerValue === 'string' && headerValue ? headerValue : null;
}

function authFailure(status, code, message) {
  return { allowed: false, valid: false, tier: 0, status, code, message };
}

export function validateB2bApiKey(req) {
  const supplied = suppliedApiKey(req);
  const registry = configuredKeyRegistry();

  if (registry.configured) {
    if (!registry.valid) {
      return authFailure(503, 'B2B_AUTH_INVALID_CONFIGURATION', 'B2B API authentication is not configured correctly.');
    }
    const requestedKeyId = safeIdentifier(req.headers?.['x-verifypulse-key-id']);
    if (!supplied || !requestedKeyId) {
      return authFailure(401, 'B2B_API_KEY_REQUIRED', 'A valid B2B API key is required.');
    }
    const record = registry.entries.find((entry) => entry.keyId === requestedKeyId);
    const suppliedDigest = keyDigest(supplied);
    const isMatch = Boolean(record && timingSafeHashMatch(suppliedDigest, record.sha256));
    if (!isMatch || record.status !== 'active' || record.expiresAt <= Date.now()) {
      return authFailure(401, 'B2B_API_KEY_INVALID', 'A valid B2B API key is required.');
    }
    const tier = record.tier || 1;
    return {
      allowed: true,
      valid: true,
      tier,
      identity: {
        scheme: 'scoped-registry',
        keyId: record.keyId,
        tenantId: record.tenantId,
        tier,
        scopes: record.scopes,
        expiresAt: new Date(record.expiresAt).toISOString()
      }
    };
  }

  const configuredDigests = configuredKeyDigests();
  if (configuredDigests.length === 0) {
    return authFailure(503, 'B2B_AUTH_NOT_CONFIGURED', 'B2B API authentication is not configured.');
  }
  if (!supplied) {
    return authFailure(401, 'B2B_API_KEY_REQUIRED', 'A valid B2B API key is required.');
  }

  const suppliedDigest = keyDigest(supplied);
  const matched = configuredDigests.some((expectedDigest) => timingSafeHashMatch(suppliedDigest, expectedDigest));
  if (!matched) {
    return authFailure(401, 'B2B_API_KEY_INVALID', 'A valid B2B API key is required.');
  }

  return {
    allowed: true,
    valid: true,
    tier: 1,
    identity: {
      scheme: 'legacy-hash-list',
      keyId: 'legacy',
      tenantId: 'legacy',
      tier: 1,
      scopes: [B2B_SCAN_SCOPE],
      expiresAt: null
    }
  };
}

export function authorizeB2bScope(authentication, requiredScope = B2B_SCAN_SCOPE) {
  if (!authentication?.allowed) return false;
  const scopes = authentication.identity?.scopes || [];
  return scopes.includes('*') || scopes.includes(requiredScope);
}

export function getConfiguredLimit(environmentVariable, fallback) {
  return getPositiveInteger(process.env[environmentVariable], fallback, 10_000);
}
