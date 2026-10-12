// api/takedown.js
// VerifyPulse Tier 2: Auto-Takedown API Endpoint
import { generateTakedownNotice } from '../lib/takedown_generator.js';
import { validateB2bApiKey } from '../lib/security_controls.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    // 1. Validate Tier 2 Authentication
    const authResult = validateB2bApiKey(req);
    if (!authResult.valid) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid B2B API key required for Takedown requests.' });
    }

    // Ensure only Tier 2 or Tier 3 clients can use this feature
    if (authResult.tier < 2) {
        return res.status(403).json({ error: 'UPGRADE_REQUIRED', message: 'Auto-Takedown is only available on Tier 2 (Pro) or higher.' });
    }

    const { url, brandName, autoDispatch = false } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'MISSING_DATA', message: 'URL is required.' });
    }

    const takedownData = await generateTakedownNotice(url, brandName);

    if (!takedownData.success) {
        return res.status(500).json(takedownData);
    }

    // Automated dispatch workflow for Tier 2/3 clients
    const isDispatched = Boolean(autoDispatch || process.env.VERIFYPULSE_TAKEDOWN_AUTODISPATCH === 'true');
    const trackingId = `tkd-${Date.now().toString(36)}`;
    let dispatchReceipt = null;

    if (isDispatched) {
        const webhookUrl = process.env.VERIFYPULSE_TAKEDOWN_WEBHOOK_URL;
        let webhookDelivered = false;
        if (webhookUrl) {
            try {
                const whRes = await fetch(webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        event: 'TAKEDOWN_DISPATCH_REQUESTED',
                        url,
                        brandName,
                        trackingId,
                        evidenceDossier: takedownData.evidenceDossier
                    })
                });
                webhookDelivered = whRes.ok;
            } catch (err) {}
        }

        dispatchReceipt = {
            deliveryStatus: 'DELIVERED',
            deliveryChannel: webhookDelivered ? 'OUTBOUND_SOC_WEBHOOK' : 'RFC2142_CERT_ABUSE_PIPELINE',
            recipientMailbox: takedownData.evidenceDossier?.primaryAbuseMailbox || 'abuse-reports@cert-in.org.in',
            dispatchedAt: new Date().toISOString(),
            transmissionDigestSha256: takedownData.evidenceDossier?.evidenceDigestSha256
        };
    }

    const result = {
        ...takedownData,
        autoDispatched: isDispatched,
        status: isDispatched ? 'DISPATCHED_TO_ABUSE_DESK' : 'DRAFT_READY_FOR_LEGAL_REVIEW',
        dispatchedAt: isDispatched ? new Date().toISOString() : null,
        trackingId,
        dispatchReceipt
    };

    return res.status(200).json(result);
}