import crypto from 'node:crypto';

// VerifyPulse B2B API Key Generator
// Run this script locally to generate a secure API key for a new client (like Steve).

function generateB2BKey(tenantName, tier) {
    // Generate a secure random string
    const rawSecret = crypto.randomBytes(32).toString('base64url');
    const apiKey = "vp_live_" + rawSecret;
    
    // Hash it for the Vercel Environment Variables (Security)
    const hash = crypto.createHash('sha256').update(apiKey).digest('hex');
    
    // Create the Registry Entry for VERIFYPULSE_B2B_KEY_REGISTRY
    const registryEntry = {
        keyId: "key_" + crypto.randomBytes(8).toString('hex'),
        tenantId: tenantName.toLowerCase().replace(/[^a-z0-9]/g, '_'),
        sha256: hash,
        scopes: ["b2b:scan"],
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 Year expiry
        status: "active"
    };

    console.log(`\n======================================================`);
    console.log(`✅ API KEY GENERATED FOR: ${tenantName} (Tier ${tier})`);
    console.log(`======================================================`);
    console.log(`🔑 GIVE THIS TO THE CLIENT (They put this in their headers):`);
    console.log(`x-api-key: ${apiKey}`);
    console.log(`x-verifypulse-key-id: ${registryEntry.keyId}`);
    console.log(`\n🔒 ADD THIS TO VERCEL ENV (VERIFYPULSE_B2B_KEY_REGISTRY):`);
    console.log(JSON.stringify([registryEntry], null, 2));
    console.log(`======================================================\n`);
}

// Generate a key for Steve (FraudShield)
generateB2BKey('FraudShield', 1);