// lib/billing_webhook.js
// VerifyPulse Razorpay Payment Webhook Receiver
import crypto from 'crypto';

// In-memory fallback for environments without Redis
const fallbackQuotaStore = globalThis.__verifyPulseQuotaStore || new Map();
globalThis.__verifyPulseQuotaStore = fallbackQuotaStore;

export async function provisionRedisQuota(apiKey, limit, notes = {}) {
    const quotaKey = `quota:${apiKey}`;
    const b2bQuotaKey = `b2b:quota:${apiKey}`;
    const ttlSeconds = 30 * 24 * 60 * 60; // 30 days

    // Always record in in-memory fallback
    fallbackQuotaStore.set(quotaKey, { limit, notes, provisionedAt: new Date().toISOString() });
    fallbackQuotaStore.set(b2bQuotaKey, limit);

    // 1. Native Redis Client (if REDIS_URL or VERIFYPULSE_REDIS_URL configured)
    const nativeUrl = process.env.VERIFYPULSE_REDIS_URL || process.env.REDIS_URL;
    if (nativeUrl) {
        try {
            const redisPkg = await import('redis');
            const createClient = redisPkg.createClient || redisPkg.default?.createClient;
            if (createClient) {
                const client = createClient({ url: nativeUrl });
                client.on('error', () => {});
                await client.connect();
                await client.set(quotaKey, String(limit), { EX: ttlSeconds });
                await client.set(b2bQuotaKey, String(limit), { EX: ttlSeconds });
                await client.disconnect();
                return true;
            }
        } catch (err) {
            console.warn('[WEBHOOK] Native Redis quota write warning:', err.message);
        }
    }

    // 2. Upstash / Vercel KV REST API (if KV_REST_API_URL or UPSTASH_REDIS_REST_URL configured)
    const restUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
    const restToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
    if (restUrl && restToken) {
        try {
            await fetch(restUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${restToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(['SETEX', quotaKey, String(ttlSeconds), String(limit)])
            });
            return true;
        } catch (err) {
            console.warn('[WEBHOOK] KV REST quota write warning:', err.message);
        }
    }

    return false;
}

function verifyWebhookSignature(receivedSig, expectedSig) {
    if (!receivedSig || !expectedSig) return false;
    try {
        const bufA = Buffer.from(String(receivedSig));
        const bufB = Buffer.from(String(expectedSig));
        return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
    } catch {
        return false;
    }
}

export default async function handleWebhook(req, res) {
    if (req.method !== 'POST') return res.status(405).send('Method not allowed');

    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.headers?.['x-razorpay-signature'];
    
    // In test/dev environments without secret, accept simulation
    if (!secret && (process.env.NODE_ENV === 'test' || !process.env.VERCEL)) {
        return res.status(200).json({ status: 'ok', simulation: true });
    }

    // Verify Webhook Signature (To prevent fake payments) using timing-safe comparison
    const bodyString = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});
    const expectedSignature = crypto.createHmac('sha256', secret || 'test_secret')
                                    .update(bodyString)
                                    .digest('hex');

    if (!verifyWebhookSignature(signature, expectedSignature)) {
        return res.status(400).json({ error: 'Invalid Signature - Hack Attempt Detected' });
    }

    // Process Successful Payment
    const event = req.body?.event;
    if (event === 'payment.captured' || event === 'order.paid') {
        const paymentDetails = req.body?.payload?.payment?.entity || {};
        const notes = paymentDetails.notes || {}; // Contains email, tier, company

        // 1. Generate Secure B2B API Key
        const newApiKey = 'vp_live_' + crypto.randomBytes(24).toString('hex');
        
        // 2. Set Quota limits based on Tier
        const limit = notes.tier === 'pro' ? 1000000 : 250000;
        await provisionRedisQuota(newApiKey, limit, notes);

        // 3. Mask key for privacy compliance in logs
        const maskedKey = `${newApiKey.slice(0, 10)}...${newApiKey.slice(-4)}`;
        const keyFingerprint = crypto.createHash('sha256').update(newApiKey).digest('hex').slice(0, 12);
        console.log(`[SUCCESS] Payment received from ${notes?.company || 'Enterprise Client'}. API Key Provisioned: ${maskedKey} (fp: ${keyFingerprint})`);

        return res.status(200).json({ status: 'ok', key_provisioned: true });
    }

    return res.status(200).json({ status: 'ignored' });
}
