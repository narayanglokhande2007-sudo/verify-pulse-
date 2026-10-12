// api/dashboard.js
// Enterprise B2B Co-Pilot Dashboard API
import { validateB2bApiKey, enforceRateLimit, setRateLimitHeaders } from '../lib/security_controls.js';
import { checkB2BQuota } from '../lib/quota_manager.js';
import { getTenantAuditTelemetryPersistent } from '../lib/audit_events.js';

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
    const tier = authResult.tier || authResult.identity?.tier || 1;
    
    // Fetch live usage & telemetry (peek mode: does not increment quota)
    const quota = await checkB2BQuota(tenantId, tier, { peek: true });
    const telemetry = await getTenantAuditTelemetryPersistent(tenantId);

    // Calculate "Value Saved" from real audit stream if available, with statistical baseline fallback
    const fraudsBlocked = telemetry.fraudsBlocked > 0 
        ? telemetry.fraudsBlocked 
        : Math.max(1, Math.floor(quota.used * 0.025));
    const valueSavedINR = telemetry.totalValueSaved > 0 
        ? telemetry.totalValueSaved 
        : fraudsBlocked * 15000;

    const tierNames = { 1: 'Standard (Tier 1)', 2: 'Pro (Tier 2)', 3: 'Ultra (Tier 3)' };

    return res.status(200).json({
        tenant: tenantId,
        tier: tier,
        tier_name: tierNames[tier] || `Tier ${tier}`,
        usage: {
            total_scans_used: quota.used,
            total_scans_limit: quota.limit,
            ai_scans_used: quota.aiUsed || 0,
            ai_scans_limit: quota.aiLimit || (tier === 1 ? 5000 : tier === 2 ? 25000 : 50000),
            scans_remaining: Math.max(0, quota.limit - quota.used),
            ai_scans_remaining: Math.max(0, (quota.aiLimit || 5000) - (quota.aiUsed || 0)),
            percentage_exhausted: ((quota.used / quota.limit) * 100).toFixed(2) + '%'
        },
        metrics: {
            frauds_prevented: fraudsBlocked,
            estimated_financial_value_saved_inr: valueSavedINR,
            calculation_basis: telemetry.fraudsBlocked > 0 ? 'LIVE_MEASURED_FRAUD_EVENTS' : 'MODEL_BASED_STATISTICAL_ESTIMATE',
            telemetry_source: telemetry.fraudsBlocked > 0 ? 'LIVE_AUDIT_STREAM' : 'STATISTICAL_BASELINE'
        },
        status: quota.allowed ? 'ACTIVE' : 'EXHAUSTED'
    });
}
