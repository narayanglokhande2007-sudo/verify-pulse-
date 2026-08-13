import crypto from 'crypto';

/**
 * VerifyPulse Ethical Canary Engine
 *
 * This module issues signed, non-production canary identifiers for resources
 * owned by VerifyPulse or an explicitly authorised customer. It must never be
 * used with real credentials, personal accounts, or third-party services
 * without written authorisation.
 */

const TOKEN_VERSION = 'vp-canary-v1';
const MAX_TTL_SECONDS = 60 * 60 * 24 * 30;

function getSecret() {
  const secret = process.env.VERIFYPULSE_CANARY_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('VERIFYPULSE_CANARY_SECRET must be set to a 32+ character secret.');
  }
  return secret;
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function sign(payload) {
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
}

function constantTimeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

/**
 * Creates an opaque signed token for a decoy that is owned by VerifyPulse or
 * an approved customer. The returned token contains no user credentials or
 * raw personal identifiers.
 */
export function createCanaryToken({ ownerId, purpose, ttlSeconds = 86400, metadata = {} }) {
  if (!ownerId || !purpose) {
    throw new Error('ownerId and purpose are required for a canary token.');
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new Error(`ttlSeconds must be an integer between 60 and ${MAX_TTL_SECONDS}.`);
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    v: TOKEN_VERSION,
    id: crypto.randomUUID(),
    ownerId,
    purpose,
    issuedAt: now,
    expiresAt: now + ttlSeconds,
    // Caller-supplied metadata must be non-sensitive and should never include
    // passwords, OTPs, payment data, government identifiers, or email content.
    metadata
  };

  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  return `${encodedPayload}.${sign(encodedPayload)}`;
}

/**
 * Verifies token authenticity and expiry. Invalid tokens return a generic
 * result so callers do not leak validation details to untrusted requesters.
 */
export function verifyCanaryToken(token) {
  try {
    const [encodedPayload, receivedSignature] = String(token || '').split('.');
    if (!encodedPayload || !receivedSignature || !constantTimeEqual(sign(encodedPayload), receivedSignature)) {
      return { valid: false, reason: 'invalid-token' };
    }

    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const now = Math.floor(Date.now() / 1000);
    if (payload.v !== TOKEN_VERSION || !payload.id || !payload.ownerId || payload.expiresAt <= now) {
      return { valid: false, reason: 'expired-or-malformed-token' };
    }

    return { valid: true, payload };
  } catch {
    return { valid: false, reason: 'invalid-token' };
  }
}

/**
 * Produces a data-minimized audit event. The caller can persist this event in
 * an approved audit store. Raw IP addresses, user agents, and credentials are
 * deliberately not stored by this module.
 */
export function createCanaryAuditEvent({ token, eventType, source = '' }) {
  const verification = verifyCanaryToken(token);
  if (!verification.valid) {
    return { accepted: false, reason: verification.reason };
  }

  const allowedEventTypes = new Set(['viewed', 'requested', 'download-attempted']);
  if (!allowedEventTypes.has(eventType)) {
    return { accepted: false, reason: 'unsupported-event-type' };
  }

  const sourceHash = source
    ? crypto.createHmac('sha256', getSecret()).update(String(source)).digest('hex')
    : null;

  return {
    accepted: true,
    event: {
      tokenId: verification.payload.id,
      ownerId: verification.payload.ownerId,
      purpose: verification.payload.purpose,
      eventType,
      observedAt: new Date().toISOString(),
      sourceHash
    }
  };
}

/**
 * Builds a link for a dedicated VerifyPulse-controlled canary endpoint.
 * The endpoint must display a transparent notice and must not execute code,
 * collect credentials, fingerprint devices, or take retaliatory action.
 */
export function createCanaryUrl(baseUrl, token) {
  const url = new URL('/api/canary-event', baseUrl);
  url.searchParams.set('token', token);
  return url.toString();
}
