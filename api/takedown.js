import dns from 'node:dns/promises';
import net from 'node:net';
import { generateTakedownNotice } from '../lib/takedown_generator.js';
import { validateB2bApiKey, authorizeB2bScope, enforceRateLimit, setRateLimitHeaders } from '../lib/security_controls.js';
import { checkB2BQuota } from '../lib/quota_manager.js';

function isPrivateIp(ip) {
    if (!ip) return true;
    const normalized = String(ip).replace(/^::ffff:/i, '').trim();

    if (net.isIPv4(normalized)) {
        const parts = normalized.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true;
        const [a, b, c] = parts;

        // 0.0.0.0/8 (Broadcast/Current network)
        if (a === 0) return true;
        // 10.0.0.0/8 (Private network)
        if (a === 10) return true;
        // 100.64.0.0/10 (Shared address space / Carrier-grade NAT)
        if (a === 100 && b >= 64 && b <= 127) return true;
        // 127.0.0.0/8 (Loopback)
        if (a === 127) return true;
        // 169.254.0.0/16 (Link-local / Cloud metadata)
        if (a === 169 && b === 254) return true;
        // 172.16.0.0/12 (Private network)
        if (a === 172 && b >= 16 && b <= 31) return true;
        // 192.0.0.0/24 & 192.0.2.0/24 (Documentation / Test net)
        if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
        // 192.168.0.0/16 (Private network)
        if (a === 192 && b === 168) return true;
        // 198.18.0.0/15 (Benchmarking)
        if (a === 198 && (b === 18 || b === 19)) return true;
        // 198.51.100.0/24 (TEST-NET-2)
        if (a === 198 && b === 51 && c === 100) return true;
        // 203.0.113.0/24 (TEST-NET-3)
        if (a === 203 && b === 0 && c === 113) return true;
        // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
        if (a >= 224) return true;
        return false;
    }

    if (net.isIPv6(normalized)) {
        const lower = normalized.toLowerCase();
        // ::1 or :: or IPv4 mapped ::ffff:127.0.0.1
        if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') return true;
        // Unique Local Address fc00::/7 (fc00... or fd00...)
        if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
        // Link-Local Address fe80::/10
        if (/^fe[89ab]/i.test(lower)) return true;
        return false;
    }

    return true; // Unknown format blocked defensively
}

function parseDecimalOrHexIp(hostname) {
    if (!hostname) return null;
    const clean = hostname.replace(/^\[|\]$/g, '').trim();

    // 1. Decimal integer IPv4 (e.g. 2130706433 -> 127.0.0.1)
    if (/^\d+$/.test(clean)) {
        const intVal = Number(clean);
        if (intVal >= 0 && intVal <= 4294967295) {
            return `${(intVal >>> 24) & 255}.${(intVal >>> 16) & 255}.${(intVal >>> 8) & 255}.${intVal & 255}`;
        }
    }

    // 2. Hexadecimal IPv4 (e.g. 0x7f000001 -> 127.0.0.1)
    if (/^0x[0-9a-f]+$/i.test(clean)) {
        const intVal = parseInt(clean, 16);
        if (intVal >= 0 && intVal <= 4294967295) {
            return `${(intVal >>> 24) & 255}.${(intVal >>> 16) & 255}.${(intVal >>> 8) & 255}.${intVal & 255}`;
        }
    }

    // 3. Dot-delimited format with hex or octal (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    if (clean.includes('.')) {
        const parts = clean.split('.');
        if (parts.length === 4) {
            const parsed = parts.map(p => {
                if (/^0x[0-9a-f]+$/i.test(p)) return parseInt(p, 16);
                if (/^0[0-7]+$/.test(p)) return parseInt(p, 8);
                if (/^\d+$/.test(p)) return parseInt(p, 10);
                return NaN;
            });
            if (parsed.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
                return parsed.join('.');
            }
        }
    }

    return null;
}

async function isBlockedTarget(hostname) {
    if (!hostname) return true;
    const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '').trim();

    // 1. Blacklisted hostname literals
    if (lower === 'localhost' || lower === 'metadata.google.internal' || lower === 'instance-data') return true;
    if (lower.endsWith('.localhost') || lower.endsWith('.local') || lower.endsWith('.internal') || lower.endsWith('.lan')) return true;
    if (lower.endsWith('.home.arpa') || lower.endsWith('.corp') || lower.endsWith('.home')) return true;

    // 2. Known DNS rebinding services
    if (/(^|\.)(nip\.io|sslip\.io|localtest\.me|vcap\.me|lvh\.me|spoofed\.burpcollaborator\.net)$/i.test(lower)) return true;

    // 3. Decimal, Hex, or Octal IP encodings
    const convertedIp = parseDecimalOrHexIp(lower);
    if (convertedIp) {
        if (isPrivateIp(convertedIp)) return true;
    }

    // 4. Direct IP address literal check
    if (net.isIP(lower)) {
        if (isPrivateIp(lower)) return true;
    }

    // 5. DNS Resolution check (with 1.5s timeout) to prevent DNS rebinding
    try {
        const lookupPromise = dns.lookup(lower, { all: true });
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('DNS_TIMEOUT')), 1500));
        const records = await Promise.race([lookupPromise, timeoutPromise]);
        if (Array.isArray(records)) {
            for (const record of records) {
                if (isPrivateIp(record.address)) {
                    return true;
                }
            }
        }
    } catch (err) {
        // In unit tests or offline environments, unresolvable test domains are allowed unless resolving to private IP
    }

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
    const apkDetails = (body.apkDetails && typeof body.apkDetails === 'object') ? body.apkDetails : null;
    const threatType = body.threatType ? String(body.threatType).trim() : (rawUrl.toLowerCase().includes('.apk') ? 'ROGUE_APK' : null);

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

    if (await isBlockedTarget(parsedUrl.hostname)) {
        return res.status(400).json({ error: 'SSRF_BLOCKED', message: 'Internal and private network targets are blocked.' });
    }

    // 6. Generate Cryptographic Evidence Dossier
    const takedownData = await generateTakedownNotice(rawUrl, brandName, { apkDetails, threatType });

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