// api/takedown.js
// VerifyPulse Tier 2: Auto-Takedown API Endpoint
import { generateTakedownNotice } from '../lib/takedown_generator.js';
import { validateB2bApiKey, authorizeB2bScope, enforceRateLimit, setRateLimitHeaders } from '../lib/security_controls.js';
import { checkB2BQuota } from '../lib/quota_manager.js';

function isBlockedPrivateHost(hostname) {
    if (!hostname) return true;
    const lower = hostname.toLowerCase();
    if (lower === 'localhost' || lower === '127.0.0.1' || lower === '::1' || lower === '0.0.0.0') return true;
    if (lower === '169.254.169.254' || lower === 'metadata.google.internal') return true;
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    return false;
}

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    // 1. Rate Limiting Protection (Prevent automated DoS or takedown flooding)
    const rateLimit = enforceRateLimit(req, { scope: 'b2b:takedown', limit: 30, windowMs: 60000 });
    if (typeof setRateLimitHeaders === 'function' && typeof res.setHeader === 'function') {
        setRateLimitHeaders(res, rateLimit);
    }
    if (!rateLimit.allowed) {
        return res.status(429).json({
            error: 'RATE_LIMITED',
            message: 'Too many takedown requests. Please slow down.'
        });
    }

    // 2. Validate Tier 2 Authentication
    const authResult = validateB2bApiKey(req);
    if (!authResult || !authResult.valid) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid B2B API key required for Takedown requests.' });
    }

    // Authorize Scope: Must have 'b2b:takedown', 'b2b:scan', or wildcard '*'
    const hasScope = authorizeB2bScope(authResult, 'b2b:takedown') || authorizeB2bScope(authResult, 'b2b:scan');
    if (!hasScope) {
        return res.status(403).json({
            error: 'INSUFFICIENT_SCOPE',
            message: 'API key does not have the required b2b:takedown scope.'
        });
    }

    // Ensure only Tier 2 or Tier 3 clients can use this feature
    const tier = authResult.tier || authResult.identity?.tier || 1;
    if (tier < 2) {
        return res.status(403).json({ error: 'UPGRADE_REQUIRED', message: 'Auto-Takedown is only available on Tier 2 (Pro) or higher.' });
    }

    // 3. Enforce B2B Quota Metering
    const tenantId = authResult.identity?.tenantId || 'anonymous_tenant';
    const quota = await checkB2BQuota(tenantId, tier);
    if (!quota.allowed) {
        return res.status(429).json({
            error: 'QUOTA_EXCEEDED',
            message: 'Monthly B2B takedown request quota exhausted. Please upgrade or contact support.'
        });
    }

    // 4. Defensive Payload Parsing & Null Safety (Loophole 17)
    const body = typeof req.body === 'string'
        ? (() => { try { return JSON.parse(req.body); } catch { return {}; } })()
        : (req.body || {});

    const rawUrl = body.url ? String(body.url).trim() : '';
    const brandName = body.brandName ? String(body.brandName).trim().slice(0, 100) : 'our protected client';
    const autoDispatch = Boolean(body.autoDispatch);

    if (!rawUrl) {
        return res.status(400).json({ error: 'MISSING_DATA', message: 'URL is required.' });
    }

    // 5. SSRF Guard & Protocol Validation (Loophole 17)
    let parsedUrl;
    try {
        if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawUrl)) {
            parsedUrl = new URL(rawUrl);
        } else {
            parsedUrl = new URL('https://' + rawUrl);
        }
    } catch {
        return res.status(400).json({ error: 'INVALID_URL', message: 'Invalid URL format.' });
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return res.status(400).json({ error: 'INVALID_URL', message: 'Only public HTTP and HTTPS URLs are allowed.' });
    }

    if (isBlockedPrivateHost(parsedUrl.hostname)) {
        return res.status(400).json({ error: 'SSRF_BLOCKED', message: 'Internal and private network targets are blocked.' });
    }

    // 6. Generate Cryptographic Evidence Dossier
    const takedownData = await generateTakedownNotice(rawUrl, brandName);

    if (!takedownData.success) {
        return res.status(500).json(takedownData);
    }

    // 7. Automated dispatch workflow for Tier 2/3 clients
    const dispatchRequested = Boolean(autoDispatch || process.env.VERIFYPULSE_TAKEDOWN_AUTODISPATCH === 'true');
    const trackingId = `tkd-${Date.now().toString(36)}`;
    let dispatchReceipt = null;

    if (dispatchRequested) {
        const webhookUrl = process.env.VERIFYPULSE_TAKEDOWN_WEBHOOK_URL;
        let webhookDelivered = false;
        if (webhookUrl) {
            try {
                const whRes = await fetch(webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        event: 'TAKEDOWN_DISPATCH_REQUESTED',
                        url: rawUrl,
                        brandName,
                        trackingId,
                        evidenceDossier: takedownData.evidenceDossier
                    })
                });
                webhookDelivered = whRes.ok;
            } catch (err) {}
        }

        dispatchReceipt = {
            deliveryStatus: webhookDelivered ? 'DELIVERED' : 'NOT_DELIVERED',
            deliveryChannel: webhookDelivered ? 'OUTBOUND_SOC_WEBHOOK' : 'NONE',
            recipientMailbox: takedownData.evidenceDossier?.primaryAbuseMailbox || 'abuse-reports@cert-in.org.in',
            dispatchedAt: webhookDelivered ? new Date().toISOString() : null,
            transmissionDigestSha256: takedownData.evidenceDossier?.evidenceDigestSha256,
            deliveryReason: webhookDelivered
                ? 'The configured outbound webhook accepted the takedown request.'
                : 'No successful outbound delivery receipt was obtained; the evidence dossier remains available for review or configured dispatch.'
        };
    }

    const result = {
        ...takedownData,
        dispatchRequested,
        autoDispatched: dispatchReceipt?.deliveryStatus === 'DELIVERED',
        status: dispatchReceipt?.deliveryStatus === 'DELIVERED'
            ? 'DISPATCHED_TO_ABUSE_DESK'
            : 'DRAFT_READY_FOR_LEGAL_REVIEW',
        dispatchedAt: dispatchReceipt?.deliveryStatus === 'DELIVERED' ? dispatchReceipt.dispatchedAt : null,
        trackingId,
        dispatchReceipt
    };

    return res.status(200).json(result);
}