// lib/quota_manager.js
// Centralized Quota Management for VerifyPulse (B2B Tiers & B2C Freemium)
// Connects to Vercel KV / Upstash Redis for permanent edge persistence.
// Falls back to in-memory store for local testing if ENV variables are missing.

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const NATIVE_REDIS_URL = process.env.VERIFYPULSE_REDIS_URL || process.env.REDIS_URL;
let nativeRedisClientPromise = null;

async function getNativeRedisClient() {
    if (!NATIVE_REDIS_URL) return null;
    if (!nativeRedisClientPromise) {
        nativeRedisClientPromise = (async () => {
            try {
                const redisPkg = await import('redis');
                const createClient = redisPkg.createClient || redisPkg.default?.createClient;
                if (!createClient) return null;
                const client = createClient({ url: NATIVE_REDIS_URL });
                client.on('error', (e) => console.error('VerifyPulse native Redis Error:', e.message));
                await client.connect();
                return client;
            } catch (e) {
                console.error('VerifyPulse native Redis Error:', e.message);
                nativeRedisClientPromise = null;
                return null;
            }
        })();
    }
    return nativeRedisClientPromise;
}

// Local fallback memory (only used if Redis is not configured)
const localB2cStore = new Map();
const localB2bStore = new Map();

export function resetLocalQuotaStores() {
    localB2cStore.clear();
    localB2bStore.clear();
}

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
    if (NATIVE_REDIS_URL) {
        try {
            const client = await getNativeRedisClient();
            if (client) {
                return await client.sendCommand([command, ...args.map(String)]);
            }
        } catch (e) {
            console.error('VerifyPulse native Redis Error:', e.message);
            nativeRedisClientPromise = null;
        }
    }
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
    const safeIp = String(ip || 'unknown').trim().toLowerCase();
    const today = new Date().toISOString().split('T')[0];
    const key = `b2c:${safeIp}:${today}`;
    
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
    const safeTenantId = String(tenantId || 'default').trim().toLowerCase();
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM
    const safeTier = [1, 2, 3].includes(Number(tier)) ? Number(tier) : 1;
    const config = TIER_CONFIG[safeTier];
    const isAiScan = Boolean(options?.isAiScan);
    const isPeek = Boolean(options?.peek || options?.readOnly);
    const isAiOnly = Boolean(options?.isAiOnly);

    const totalKey = `b2b:${safeTenantId}:${month}:total`;
    const aiKey = `b2b:${safeTenantId}:${month}:ai`;

    let totalCount = 0;
    let aiCount = 0;

    if (isPeek) {
        if (REDIS_URL) {
            const existingTotal = await redisCommand('GET', totalKey);
            totalCount = Number(existingTotal || 0);
            const existingAi = await redisCommand('GET', aiKey);
            aiCount = Number(existingAi || 0);
        } else {
            totalCount = localB2bStore.get(totalKey) || 0;
            aiCount = localB2bStore.get(aiKey) || 0;
        }
    } else if (isAiOnly) {
        if (REDIS_URL) {
            const existingTotal = await redisCommand('GET', totalKey);
            totalCount = Number(existingTotal || 0);
            aiCount = (await redisCommand('INCR', aiKey)) || 1;
            if (aiCount === 1) {
                await redisCommand('EXPIRE', aiKey, 2592000);
            }
        } else {
            totalCount = localB2bStore.get(totalKey) || 0;
            aiCount = (localB2bStore.get(aiKey) || 0) + 1;
            localB2bStore.set(aiKey, aiCount);
        }
    } else {
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

export async function getB2BQuotaUsage(tenantId, tier = 1) {
    return checkB2BQuota(tenantId, tier, { peek: true });
}