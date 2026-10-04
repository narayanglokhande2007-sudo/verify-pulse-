// lib/financial_forensics.js
// VerifyPulse Tier 2: Financial & Telecom Threat Extraction Engine
// Deep Analysis module for UPI, Phone Numbers, IFSC, and APK malware drops.

const KNOWN_UPI_HANDLES = new Set([
    'ybl', 'okaxis', 'okicici', 'oksbi', 'okhdfcbank', 'paytm', 'apl', 'yapl', 'axl', 'ibl', 'sib', 'upi'
]);

export function analyzeFinancialThreats(text, urls = []) {
    const threats = {
        upiIds: [],
        phoneNumbers: [],
        ifscCodes: [],
        hasApkDrop: false,
        riskScore: 0,
        warnings: []
    };

    if (!text && urls.length === 0) return threats;
    
    const combinedString = (text + " " + urls.join(" ")).toLowerCase();

    // 1. APK Malware Drop Detection
    // Analyzes if the text or URL is trying to force an Android application download
    const apkRegex = /\.apk(?:$|\?)/i;
    const apkKeywords = ['download app', 'install app', 'update kyc app', 'rewards.apk', 'bank.apk'];
    
    const hasApkUrl = urls.some(url => apkRegex.test(url));
    const hasApkText = apkKeywords.some(kw => combinedString.includes(kw)) && combinedString.includes('.apk');
    
    if (hasApkUrl || hasApkText) {
        threats.hasApkDrop = true;
        threats.riskScore += 80; // Extremely high risk in Indian context (Netbanking Trojans)
        threats.warnings.push("MALICIOUS_APK_DROP: Attempting to download a potentially harmful Android application.");
    }

    // 2. UPI ID Extraction & Heuristics
    // Basic regex for UPI: string@bank
    const upiRegex = /[a-zA-Z0-9.\-_]{3,50}@[a-zA-Z]{2,20}/g;
    const rawUpis = text.match(upiRegex) || [];
    
    for (const upi of rawUpis) {
        const handle = upi.split('@')[1].toLowerCase();
        if (KNOWN_UPI_HANDLES.has(handle)) {
            threats.upiIds.push(upi);
        }
    }
    
    if (threats.upiIds.length > 0) {
        // Scammers often use generic names or mobile numbers in UPI IDs
        threats.warnings.push("FINANCIAL_IDENTIFIER: Contains active UPI IDs requesting payment.");
        threats.riskScore += 20;
    }

    // 3. Indian Phone Number Extraction
    // Matches +91, 0, or raw 10 digit numbers starting with 6-9
    const phoneRegex = /(?:(?:\+|00)91\s?|0)?([6-9]\d{9})/g;
    let match;
    while ((match = phoneRegex.exec(text)) !== null) {
        threats.phoneNumbers.push(match[1]); // Push only the 10 digit core
    }

    // Deduplicate arrays
    threats.upiIds = [...new Set(threats.upiIds)];
    threats.phoneNumbers = [...new Set(threats.phoneNumbers)];

    // 4. IFSC / Mule Account Pattern Recognition
    const ifscRegex = /[A-Z]{4}0[A-Z0-9]{6}/g;
    const rawIfsc = text.toUpperCase().match(ifscRegex) || [];
    threats.ifscCodes = [...new Set(rawIfsc)];

    if (threats.ifscCodes.length > 0) {
        threats.warnings.push("BANK_ROUTING: Contains IFSC routing codes often used for direct mule transfers.");
        threats.riskScore += 15;
    }

    // Cap the risk score at 100
    threats.riskScore = Math.min(threats.riskScore, 100);

    return threats;
}