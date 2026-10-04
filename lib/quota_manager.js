// lib/quota_manager.js
// Centralized Quota Management for VerifyPulse (B2B Tiers & B2C Freemium)
// This is an in-memory/best-effort tracker for edge functions.
// In production, this should be wired to Vercel KV or Upstash Redis.

const b2cQuotaStore = new Map();
const b2bQuotaStore = new Map();

// Limits (Configurable via ENV)
const B2C_DAILY_LIMIT = 50; 
const TIER_1_MONTHLY_LIMIT = 5000;
const TIER_2_MONTHLY_LIMIT = 25000;
const TIER_3_MONTHLY_LIMIT = 50000;

export function checkB2CQuota(ip) {
    const today = new Date().toISOString().split('T')[0];
    const key = `b2c:${ip}:${today}`;
    
    let count = b2cQuotaStore.get(key) || 0;
    count += 1;
    b2cQuotaStore.set(key, count);

    // Prevent memory leak
    if (b2cQuotaStore.size > 5000) {
        b2cQuotaStore.clear(); // Basic flush, in prod use Redis TTL
    }

    return {
        allowed: count <= B2C_DAILY_LIMIT,
        used: count,
        limit: B2C_DAILY_LIMIT
    };
}

export function checkB2BQuota(tenantId, tier = 1) {
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM
    const key = `b2b:${tenantId}:${month}`;
    
    let count = b2bQuotaStore.get(key) || 0;
    count += 1;
    b2bQuotaStore.set(key, count);
    
    let limit = TIER_1_MONTHLY_LIMIT;
    if (tier === 2) limit = TIER_2_MONTHLY_LIMIT;
    if (tier === 3) limit = TIER_3_MONTHLY_LIMIT;

    return {
        allowed: count <= limit,
        used: count,
        limit: limit
    };
}