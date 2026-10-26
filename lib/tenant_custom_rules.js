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

function getTenantRules(tenantId) {
    if (!tenantId) return null;
    const normalizedId = String(tenantId).toLowerCase();

    // 1. Dynamic Environment Configuration (for cloud / enterprise deployment)
    if (process.env.VERIFYPULSE_TENANT_RULES) {
        try {
            const dynamicRules = JSON.parse(process.env.VERIFYPULSE_TENANT_RULES);
            if (dynamicRules && dynamicRules[normalizedId]) {
                return dynamicRules[normalizedId];
            }
        } catch {}
    }

    // 2. Built-in seed rule database
    return tenantRulesDb[normalizedId] || null;
}

export function applyTenantCustomRules(tenantId, tier, rawInput, urls, currentVerdictData) {
    // Only Tier 3 gets Custom Fine-Tuning
    if (tier < 3 || !tenantId) return currentVerdictData;
    
    const rules = getTenantRules(tenantId);
    if (!rules) return currentVerdictData; // No custom rules set for this tenant

    const lowerInput = String(rawInput || '').toLowerCase();
    let modifiedVerdict = { ...(currentVerdictData || {}) };
    if (!Array.isArray(modifiedVerdict.findings)) modifiedVerdict.findings = [];
    if (!Array.isArray(modifiedVerdict.evidenceSources)) modifiedVerdict.evidenceSources = [];

    // 1. Process Whitelists (Overriding AI False Positives)
    if (rules.whitelistedDomains && urls && urls.length > 0) {
        const isWhitelisted = urls.some(url => {
            try {
                let hostname = '';
                if (url && typeof url === 'object' && url.hostname) {
                    hostname = url.hostname;
                } else {
                    const urlStr = String(url || '');
                    hostname = new URL(urlStr.startsWith('http') ? urlStr : 'https://' + urlStr).hostname;
                }
                const normalizedHost = hostname.toLowerCase();
                return rules.whitelistedDomains.some(d => {
                    const normalizedDomain = String(d || '').toLowerCase().trim();
                    return normalizedDomain && (normalizedHost === normalizedDomain || normalizedHost.endsWith('.' + normalizedDomain));
                });
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
        const cleanInput = lowerInput.replace(/[\u200B-\u200D\uFEFF\u2060\u00A0\u180E]/g, '');
        const hasBlacklisted = rules.blacklistedKeywords.some(kw => {
            const cleanKw = String(kw || '').toLowerCase().trim();
            return cleanKw && cleanInput.includes(cleanKw);
        });
        if (hasBlacklisted) {
            modifiedVerdict.verdict = 'SUSPICIOUS';
            modifiedVerdict.scamType = 'Brand Impersonation (Tenant Blacklist)';
            modifiedVerdict.confidence = Math.max(Number(modifiedVerdict.confidence) || 0, 99);
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