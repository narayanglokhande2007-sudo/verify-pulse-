// lib/quota_manager.js
// Centralized Quota Management for VerifyPulse (B2B Tiers & B2C Freemium)
// Connects to Vercel KV / Upstash Redis for permanent edge persistence.
// Falls back to in-memory store for local testing if ENV variables are missing.

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

// Local fallback memory (only used if Redis is not configured)
const localB2cStore = new Map();
const localB2bStore = new Map();

// Limits (Configurable via ENV)
const B2C_DAILY_LIMIT = 50; 
const TIER_1_MONTHLY_LIMIT = 5000;
const TIER_2_MONTHLY_LIMIT = 25000;
const TIER_3_MONTHLY_LIMIT = 50000;

async function redisCommand(command, ...args) {
    if (!REDIS_URL || !REDIS_TOKEN) return null;
    try {
        const response = await fetch(REDIS_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${REDIS_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify([command, ...args])
        });
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        return data.result;
    } catch (e) {
        console.error("VerifyPulse Redis Error:", e.message);
        return null;
    }
}

export async function checkB2CQuota(ip) {
    const today = new Date().toISOString().split('T')[0];
    const key = `b2c:${ip}:${today}`;
    
    let count = 0;

    if (REDIS_URL) {
        // Atomic increment in Redis
        count = await redisCommand('INCR', key);
        if (count === 1) {
            await redisCommand('EXPIRE', key, 86400); // Expire in 24 hours
        }
    } else {
        count = localB2cStore.get(key) || 0;
        count += 1;
        localB2cStore.set(key, count);
        if (localB2cStore.size > 5000) localB2cStore.clear(); // Anti-leak for local dev
    }

    return {
        allowed: count <= B2C_DAILY_LIMIT,
        used: count,
        limit: B2C_DAILY_LIMIT
    };
}

export async function checkB2BQuota(tenantId, tier = 1) {
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM
    const key = `b2b:${tenantId}:${month}`;
    
    let limit = TIER_1_MONTHLY_LIMIT;
    if (tier === 2) limit = TIER_2_MONTHLY_LIMIT;
    if (tier === 3) limit = TIER_3_MONTHLY_LIMIT;

    let count = 0;

    if (REDIS_URL) {
        count = await redisCommand('INCR', key);
        if (count === 1) {
            await redisCommand('EXPIRE', key, 2592000); // Expire in 30 days
        }
    } else {
        count = localB2bStore.get(key) || 0;
        count += 1;
        localB2bStore.set(key, count);
    }

    return {
        allowed: count <= limit,
        used: count,
        limit: limit
    };
}