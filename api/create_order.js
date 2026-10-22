// api/create_order.js (Vercel Serverless Function)
// VerifyPulse SaaS Subscription Order Creation (Razorpay Integration)

import { enforceRateLimit, setRateLimitHeaders } from '../lib/security_controls.js';

// Standard SaaS Pricing (Hardcoded to prevent client-side tampering)
const TIERS = {
    'standard': { amount: 2500000, name: 'Tier 1: Standard' }, // Amount in paise (25,000 * 100)
    'pro': { amount: 9900000, name: 'Tier 2: Pro' }            // Amount in paise (99,000 * 100)
};

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    // 1. Rate Limiting Protection (Prevent bot card-testing and DoS attacks)
    const rateLimit = enforceRateLimit(req, { scope: 'b2c:create_order', limit: 15, windowMs: 60000 });
    if (typeof setRateLimitHeaders === 'function') {
        setRateLimitHeaders(res, rateLimit);
    }
    if (!rateLimit.allowed) {
        return res.status(429).json({
            error: 'RATE_LIMITED',
            message: 'Too many order initialization attempts. Please retry in a few moments.'
        });
    }

    // 2. Safe Body Parsing & Input Sanitization
    const body = typeof req.body === 'string'
        ? (() => { try { return JSON.parse(req.body); } catch { return {}; } })()
        : (req.body || {});

    const tierId = String(body.tierId || '').trim().toLowerCase();
    const email = String(body.email || '').trim().toLowerCase();
    const company = String(body.company || '').trim().slice(0, 100);

    if (!tierId || !TIERS[tierId]) {
        return res.status(400).json({ error: 'Invalid Tier Selected' });
    }

    // Email format validation (if provided)
    if (email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email) || email.length > 128) {
            return res.status(400).json({ error: 'Invalid Email Format' });
        }
    }

    try {
        const keyId = process.env.RAZORPAY_KEY_ID;
        const keySecret = process.env.RAZORPAY_KEY_SECRET;

        const options = {
            amount: TIERS[tierId].amount,
            currency: 'INR',
            receipt: `rcpt_${Date.now()}`,
            notes: {
                tier: tierId,
                email: email,
                company: company
            }
        };

        // If credentials are configured, invoke Razorpay REST API
        if (keyId && keySecret) {
            const basicAuth = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
            const razorpayResponse = await fetch('https://api.razorpay.com/v1/orders', {
                method: 'POST',
                headers: {
                    'Authorization': `Basic ${basicAuth}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(options)
            });

            if (!razorpayResponse.ok) {
                const errorPayload = await razorpayResponse.json().catch(() => ({}));
                console.error("Razorpay Gateway Error:", errorPayload);
                return res.status(502).json({ error: 'Payment gateway rejected order creation' });
            }

            const order = await razorpayResponse.json();

            return res.status(200).json({
                id: order.id,
                amount: order.amount,
                currency: order.currency,
                tierName: TIERS[tierId].name
            });
        }

        // Test/Development Mode when Razorpay keys are not yet bound in environment
        if (process.env.NODE_ENV === 'test' || !process.env.VERCEL) {
            return res.status(200).json({
                id: `order_sim_${Date.now()}`,
                amount: TIERS[tierId].amount,
                currency: 'INR',
                tierName: TIERS[tierId].name,
                mode: 'test_simulation'
            });
        }

        return res.status(503).json({ error: 'Payment gateway not configured' });

    } catch (error) {
        console.error("Order Creation Error:", error);
        return res.status(500).json({ error: 'Failed to initialize payment gateway' });
    }
}
