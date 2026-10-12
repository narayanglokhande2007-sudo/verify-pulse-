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
const B2C_DAILY_LIMIT = Number(process.env.VERIFYPULSE_B2C_DAILY_LIMIT || 50); 
const TIER_CONFIG = {
    1: {
        total: Number(process.env.VERIFYPULSE_TIER_1_TOTAL_LIMIT || 250000),
        ai: Number(process.env.VERIFYPULSE_TIER_1_AI_LIMIT || 5000)
    },
    2: {
        total: Number(process.env.VERIFYPULSE_TIER_2_TOTAL_LIMIT || 1000000),
        ai: Number(process.env.VERIFYPULSE_TIER_2_AI_LIMIT || 25000)
    },
    3: {
        total: Number(process.env.VERIFYPULSE_TIER_3_TOTAL_LIMIT || 5000000),
        ai: Number(process.env.VERIFYPULSE_TIER_3_AI_LIMIT || 50000)
    }
};

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

export async function checkB2BQuota(tenantId, tier = 1, options = {}) {
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM
    const safeTier = [1, 2, 3].includes(Number(tier)) ? Number(tier) : 1;
    const config = TIER_CONFIG[safeTier];
    const isAiScan = Boolean(options?.isAiScan);

    const totalKey = `b2b:${tenantId}:${month}:total`;
    const aiKey = `b2b:${tenantId}:${month}:ai`;

    let totalCount = 0;
    let aiCount = 0;

    if (REDIS_URL) {
        totalCount = (await redisCommand('INCR', totalKey)) || 1;
        if (totalCount === 1) {
            await redisCommand('EXPIRE', totalKey, 2592000); // Expire in 30 days
        }

        if (isAiScan) {
            aiCount = (await redisCommand('INCR', aiKey)) || 1;
            if (aiCount === 1) {
                await redisCommand('EXPIRE', aiKey, 2592000);
            }
        } else {
            const existingAi = await redisCommand('GET', aiKey);
            aiCount = Number(existingAi || 0);
        }
    } else {
        totalCount = (localB2bStore.get(totalKey) || 0) + 1;
        localB2bStore.set(totalKey, totalCount);

        if (isAiScan) {
            aiCount = (localB2bStore.get(aiKey) || 0) + 1;
            localB2bStore.set(aiKey, aiCount);
        } else {
            aiCount = localB2bStore.get(aiKey) || 0;
        }
    }

    const totalAllowed = totalCount <= config.total;
    const aiAllowed = !isAiScan || aiCount <= config.ai;
    const allowed = totalAllowed && aiAllowed;

    return {
        allowed,
        totalAllowed,
        aiAllowed,
        used: totalCount,
        limit: config.total,
        aiUsed: aiCount,
        aiLimit: config.ai,
        tier: safeTier
    };
}