// api/zeroday.js
// VerifyPulse Tier 2: Zero-Day Keyword Monitoring Endpoint
// Searches Certificate Transparency (CT) logs in real-time to find freshly registered scam domains.

import { validateB2bApiKey } from '../lib/security_controls.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    // 1. Validate Tier 2 Authentication
    const authResult = validateB2bApiKey(req);
    if (!authResult.valid) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid B2B API key required for Zero-Day Monitor.' });
    }

    // Ensure only Tier 2 or Tier 3 clients can use this feature
    if (authResult.tier < 2) {
        return res.status(403).json({ error: 'UPGRADE_REQUIRED', message: 'Zero-Day Monitoring is only available on Tier 2 (Pro) or higher.' });
    }

    const { keyword, officialDomain } = req.body;
    if (!keyword) {
        return res.status(400).json({ error: 'MISSING_DATA', message: 'A keyword is required (e.g., "fraudshield").' });
    }

    try {
        // Deep Analysis Trick: Use Certificate Transparency Logs (crt.sh)
        // Scammers use Let's Encrypt to get free SSL certificates for their fake phishing domains.
        // As soon as they get an SSL cert, it is logged publicly. We can search this to find scams BEFORE they are launched!
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 12000); // 12 seconds max timeout for serverless
        
        const crtRes = await fetch(`https://crt.sh/?q=%25${encodeURIComponent(keyword)}%25&output=json`, {
            signal: controller.signal,
            headers: { 'User-Agent': 'VerifyPulse-ZeroDay-Engine/1.0' }
        });
        clearTimeout(timeoutId);

        if (!crtRes.ok) throw new Error('CT Log fetch failed');
        
        const data = await crtRes.json();
        
        // Process and filter the raw log data
        const suspiciousDomains = new Set();
        const now = new Date();
        
        for (const entry of data) {
            // Only flag freshly created phishing domains (within the last 48 hours)
            const entryDate = new Date(entry.not_before);
            const hoursDiff = (now - entryDate) / (1000 * 60 * 60);
            
            if (hoursDiff <= 48) {
                const domainNames = String(entry.name_value).split('\n');
                for (let d of domainNames) {
                    d = d.trim().toLowerCase().replace('*.', '');
                    
                    // Skip the client's official domain so we don't flag their real website
                    if (officialDomain && d === officialDomain.toLowerCase()) continue; 
                    
                    // Add to discovered threats
                    suspiciousDomains.add(d);
                }
            }
        }

        const discoveriesArray = Array.from(suspiciousDomains).slice(0, 50); // Send max 50 recent threats

        return res.status(200).json({
            keywordMonitor: keyword,
            scanWindow: 'Last 48 Hours',
            totalNewThreatsFound: suspiciousDomains.size,
            suspiciousDomains: discoveriesArray,
            status: 'ACTIVE_ZERO_DAY_MONITORING'
        });

    } catch (error) {
        return res.status(500).json({ 
            error: 'MONITOR_TIMEOUT', 
            message: 'The Zero-Day global registry is currently processing too many requests. Please retry shortly.' 
        });
    }
}