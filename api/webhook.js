// api/webhook.js (Vercel Serverless Function)
import crypto from 'crypto';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send('Method not allowed');

    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.headers['x-razorpay-signature'];
    
    // Verify Webhook Signature (To prevent fake payments)
    const bodyString = JSON.stringify(req.body);
    const expectedSignature = crypto.createHmac('sha256', secret)
                                    .update(bodyString)
                                    .digest('hex');

    if (signature !== expectedSignature) {
        return res.status(400).json({ error: 'Invalid Signature - Hack Attempt Detected' });
    }

    // Process Successful Payment
    const event = req.body.event;
    if (event === 'payment.captured' || event === 'order.paid') {
        const paymentDetails = req.body.payload.payment.entity;
        const notes = paymentDetails.notes; // Contains email, tier, company

        // 1. Generate Secure B2B API Key
        const newApiKey = 'vp_live_' + crypto.randomBytes(24).toString('hex');
        
        // 2. Set Quota limits based on Tier (Pseudo-code for Redis)
        const limit = notes.tier === 'pro' ? 1000000 : 250000;
        // await redis.set(`quota:${newApiKey}`, limit);

        // 3. (Future) Trigger Email to client with their API Key
        const maskedKey = `${newApiKey.slice(0, 10)}...${newApiKey.slice(-4)}`;
        const keyFingerprint = crypto.createHash('sha256').update(newApiKey).digest('hex').slice(0, 12);
        console.log(`[SUCCESS] Payment received from ${notes?.company || 'Enterprise Client'}. API Key Provisioned: ${maskedKey} (fp: ${keyFingerprint})`);

        return res.status(200).json({ status: 'ok', key_provisioned: true });
    }

    return res.status(200).json({ status: 'ignored' });
}
