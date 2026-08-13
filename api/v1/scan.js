import {
  enforceRateLimit,
  getConfiguredLimit,
  setRateLimitHeaders,
  validateB2bApiKey,
} from '../security_controls.js';

function setApiSecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

function applyB2bCors(req, res) {
  const origin = req.headers?.origin;
  const configuredOrigins = String(process.env.VERIFYPULSE_B2B_ALLOWED_ORIGINS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  // Server-to-server integrations do not send an Origin header. Browser-based
  // integrations must be explicitly allow-listed instead of using `*`.
  if (!origin) return { allowed: true };
  if (!configuredOrigins.includes(origin)) {
    return { allowed: false };
  }

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');
  res.setHeader('Access-Control-Max-Age', '600');
  return { allowed: true };
}

function parsePublicHttpUrl(value) {
  if (typeof value !== 'string' || value.length > 2_048) {
    throw new Error('A URL of 2,048 characters or fewer is required.');
  }
  const target = new URL(value);
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
    throw new Error('Only credential-free HTTP(S) URLs are supported.');
  }
  return target.toString();
}

export default async function handler(req, res) {
  setApiSecurityHeaders(res);
  const cors = applyB2bCors(req, res);
  if (!cors.allowed) {
    return res.status(403).json({ error: 'ORIGIN_NOT_ALLOWED', message: 'This browser origin is not approved for the B2B API.' });
  }

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: 'Only POST requests are accepted.' });
  }

  const rateLimit = enforceRateLimit(req, {
    scope: 'b2b-scan',
    limit: getConfiguredLimit('VERIFYPULSE_B2B_RATE_LIMIT_MAX', 20),
  });
  setRateLimitHeaders(res, rateLimit);
  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: 'RATE_LIMITED',
      message: 'Too many B2B scan requests. Please retry shortly.',
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    });
  }

  const auth = validateB2bApiKey(req);
  if (!auth.allowed) {
    return res.status(auth.status).json({ error: auth.code, message: auth.message });
  }

  try {
    const normalizedUrl = parsePublicHttpUrl(req.body?.url);
    const host = req.headers?.host;
    if (!host) throw new Error('Unable to determine the application host.');

    const protocol = req.headers?.['x-forwarded-proto'] === 'http' ? 'http' : 'https';
    const masterEngineUrl = `${protocol}://${host}/api/verify`;
    const response = await fetch(masterEngineUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: normalizedUrl, checkType: 'unified' }),
    });

    if (!response.ok) {
      throw new Error('VerifyPulse master engine did not return a successful response.');
    }

    const masterResult = await response.json();
    const verdict = masterResult.verdict || 'UNCERTAIN';
    return res.status(200).json({
      status: verdict,
      threat_level: ['DANGEROUS', 'SCAM', 'FRAUD'].includes(verdict) ? 'HIGH' : verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
      scam_type: masterResult.scamType || 'Unknown',
      confidence: masterResult.confidence || 0,
      message: masterResult.analysis || 'Analysis complete.',
      action_steps: masterResult.whatToDo || [],
    });
  } catch (error) {
    const isClientError = /required|HTTP\(S\)|credential-free|2,048/i.test(error.message);
    return res.status(isClientError ? 400 : 502).json({
      error: isClientError ? 'BAD_REQUEST' : 'UPSTREAM_ERROR',
      message: isClientError ? error.message : 'The master verification engine could not process this B2B request.',
    });
  }
}
