// lib/tenant_custom_rules.js
// VerifyPulse Tier 3: Custom Tenant Rules & AI Fine-Tuning Engine
// Allows Ultra-Tier clients to define custom whitelists, strictness levels, and brand overrides.

// Mock Database for Tier 3 Custom Rules
// In production, this would be fetched from Vercel KV / Redis
const tenantRulesDb = {
    'fraudshield': {
        whitelistedDomains: ['fraudshield-demo.com', 'fraudshield-auth.net'],
        blacklistedKeywords: ['fraudshield-support', 'fraudshield-kyc', 'fraudshield-update'],
        strictMode: true, // Elevates CONFIDENCE scores for suspicious items
        customMessage: "FraudShield Security Policy: Official domains are fraudshield.com only."
    },
    'hdfc_bank_test': {
        whitelistedDomains: ['hdfcbank.com', 'hdfc.com'],
        blacklistedKeywords: ['hdfc-reward', 'hdfc-pan-update'],
        strictMode: true,
        customMessage: "HDFC Bank Policy: We never ask for OTP via SMS links."
    }
};

export function applyTenantCustomRules(tenantId, tier, rawInput, urls, currentVerdictData) {
    // Only Tier 3 gets Custom Fine-Tuning
    if (tier < 3 || !tenantId) return currentVerdictData;
    
    const rules = tenantRulesDb[tenantId.toLowerCase()];
    if (!rules) return currentVerdictData; // No custom rules set for this tenant

    const lowerInput = String(rawInput || '').toLowerCase();
    let modifiedVerdict = { ...currentVerdictData };
    if (!modifiedVerdict.findings) modifiedVerdict.findings = [];

    // 1. Process Whitelists (Overriding AI False Positives)
    if (rules.whitelistedDomains && urls && urls.length > 0) {
        const isWhitelisted = urls.some(url => {
            try {
                const hostname = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
                return rules.whitelistedDomains.includes(hostname.toLowerCase());
            } catch(e) { return false; }
        });

        if (isWhitelisted) {
            modifiedVerdict.verdict = 'SAFE';
            modifiedVerdict.scamType = 'Tenant Custom Whitelist';
            modifiedVerdict.confidence = 100;
            modifiedVerdict.analysis = `Approved by ${tenantId} enterprise security policy.`;
            modifiedVerdict.findings.push(`Verified official ${tenantId} asset.`);
            // Wipe out shadow evaluation / evidence that might have marked it risky
            modifiedVerdict.evidenceSources = ['tenant_custom_whitelist'];
            return modifiedVerdict; // Fast return, whitelist overrides everything
        }
    }

    // 2. Process Blacklists (Zero-Day Brand Protection Overrides)
    if (rules.blacklistedKeywords) {
        const hasBlacklisted = rules.blacklistedKeywords.some(kw => lowerInput.includes(kw));
        if (hasBlacklisted) {
            modifiedVerdict.verdict = 'SUSPICIOUS';
            modifiedVerdict.scamType = 'Brand Impersonation (Tenant Blacklist)';
            modifiedVerdict.confidence = Math.max(modifiedVerdict.confidence, 99);
            modifiedVerdict.findings.push(`Matches custom blacklisted term for ${tenantId}.`);
            if (!modifiedVerdict.evidenceSources.includes('tenant_custom_blacklist')) {
                modifiedVerdict.evidenceSources.push('tenant_custom_blacklist');
            }
        }
    }

    // 3. Strict Mode Tuning
    if (rules.strictMode && modifiedVerdict.verdict === 'SUSPICIOUS') {
        // Artificially inflate confidence to trigger stricter downstream client actions
        modifiedVerdict.confidence = Math.min(modifiedVerdict.confidence + 15, 99);
    }

    // 4. Custom Policy Appending
    if (rules.customMessage && !modifiedVerdict.findings.includes(rules.customMessage)) {
        modifiedVerdict.findings.push(rules.customMessage);
    }

    return modifiedVerdict;
}