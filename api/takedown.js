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

    const { url, brandName } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'MISSING_DATA', message: 'URL is required.' });
    }

    const takedownData = await generateTakedownNotice(url, brandName);

    if (!takedownData.success) {
        return res.status(500).json(takedownData);
    }

    // Return the generated notice for the client to review/send
    return res.status(200).json(takedownData);
}