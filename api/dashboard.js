// api/dashboard.js
// Enterprise B2B Co-Pilot Dashboard API
import { validateB2bApiKey, enforceRateLimit, setRateLimitHeaders } from '../lib/security_controls.js';
import { checkB2BQuota } from '../lib/quota_manager.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

    // Rate Limit the Dashboard
    const rateLimit = enforceRateLimit(req, { scope: 'dashboard', limit: 10 });
    setRateLimitHeaders(res, rateLimit);
    if (!rateLimit.allowed) return res.status(429).json({ error: 'RATE_LIMITED' });

    // Authenticate the Client
    const authResult = validateB2bApiKey(req);
    if (!authResult || !authResult.allowed) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Invalid or missing API Key.' });
    }

    const tenantId = authResult.identity.tenantId;
    
    // For now, assume Tier 1 if not explicitly set. In a real DB, fetch tenant's tier.
    const tier = 1; 
    
    // Fetch live usage
    const quota = checkB2BQuota(tenantId, tier);

    // Calculate "Value Saved" (Psychological B2B Metric)
    // Assume 2.5% of all scans were high-risk, and each prevented fraud saved ₹10,000.
    const estimatedFraudsBlocked = Math.floor(quota.used * 0.025);
    const valueSavedINR = estimatedFraudsBlocked * 10000;

    return res.status(200).json({
        tenant: tenantId,
        tier: tier,
        usage: {
            ai_scans_used: quota.used,
            ai_scans_limit: quota.limit,
            remaining: quota.limit - quota.used,
            percentage_exhausted: ((quota.used / quota.limit) * 100).toFixed(2) + '%'
        },
        metrics: {
            frauds_prevented: estimatedFraudsBlocked,
            estimated_financial_value_saved_inr: valueSavedINR
        },
        status: quota.allowed ? 'ACTIVE' : 'EXHAUSTED'
    });
}