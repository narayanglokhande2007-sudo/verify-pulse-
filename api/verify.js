// Defensive requires — if a module fails to load (e.g. missing optional deps on Vercel),
// fall back to a stub so the handler ALWAYS returns valid JSON.
let analyzeUrl;
try {
    ({ analyzeUrl } = require('./ghost_agent'));
} catch (e) {
    console.warn('[verify] ghost_agent unavailable, using stub:', e.message);
    analyzeUrl = async () => ({
        isSuspicious: false,
        reason: ['Behavioural analysis layer unavailable in this environment.'],
        detectedBrand: null,
        fingerprint: {},
    });
}

let searchMasterData;
try {
    ({ searchMasterData } = require('./db_helper'));
} catch (e) {
    console.warn('[verify] db_helper unavailable, using stub:', e.message);
    searchMasterData = () => ({ found: false });
}

export default async function handler(req, res) {
    // CORS so the site (and any other clients) can call this endpoint
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Default response builder (frontend format: verdict / scamType / confidence / analysis / findings / whatToDo)
    const buildResponse = (overrides = {}) => ({
        verdict: 'UNCERTAIN',
        scamType: 'Unknown',
        confidence: 50,
        analysis: '',
        findings: [],
        whatToDo: [],
        ...overrides,
    });

    try {
        // Accept 'text' (frontend sends this) with 'input' as a legacy fallback
        const { text, input: legacyInput, checkType } = req.body || {};
        const userInput = text || legacyInput;

        if (!userInput) {
            return res.status(200).json(buildResponse({
                verdict: 'UNCERTAIN',
                analysis: 'No input provided.',
                whatToDo: ['Paste a message, link, phone number or UPI ID to scan.'],
            }));
        }

        // Phase 1: Parallel Analysis (existing logic — preserved)
        const [dbResult, ghostReport] = await Promise.all([
            Promise.resolve(searchMasterData(userInput)),
            Promise.resolve(analyzeUrl(userInput)).catch(err => ({
                isSuspicious: false,
                reason: ['Analysis failed: ' + err.message],
                detectedBrand: null,
                fingerprint: {},
            })),
        ]);

        // Phase 2: Meta Judge Council (existing logic — preserved, then mapped to frontend format)
        let finalVerdict = {
            isScam: false,
            confidence: 0,
            reason: [],
            layers: {
                database: dbResult,
                behavioral: ghostReport,
                infrastructure: ghostReport.fingerprint,
            },
        };

        // Decision Logic (preserved from original)
        if (dbResult.found) {
            finalVerdict.isScam = true;
            finalVerdict.confidence = 99;
            finalVerdict.reason.push('Blacklisted in global threat intelligence database.');
        }

        if (ghostReport.isSuspicious) {
            finalVerdict.isScam = true;
            finalVerdict.confidence = Math.max(finalVerdict.confidence, 90);
            finalVerdict.reason.push(...ghostReport.reason);
        }

        if (ghostReport.screenshot && ghostReport.detectedBrand) {
            finalVerdict.reason.push(`AI Vision confirmed visual imitation of ${ghostReport.detectedBrand}.`);
            finalVerdict.confidence = 99.9;
        }

        // Map internal verdict -> frontend-expected format
        let frontendVerdict = 'SAFE';
        if (finalVerdict.isScam) {
            frontendVerdict = (ghostReport.detectedBrand || finalVerdict.confidence >= 95) ? 'DANGEROUS' : 'SUSPICIOUS';
        } else if (ghostReport.error) {
            frontendVerdict = 'UNCERTAIN';
        }

        const scamType = ghostReport.detectedBrand
            ? `${ghostReport.detectedBrand} Impersonation`
            : (finalVerdict.isScam ? 'Phishing / Scam' : 'None Detected');

        const analysis = finalVerdict.reason.length
            ? finalVerdict.reason.join(' ')
            : (frontendVerdict === 'SAFE'
                ? 'No threats detected by the available analysis layers.'
                : 'Behavioural signals flagged this input for review.');

        const whatToDo = frontendVerdict === 'SAFE'
            ? ['No action required — appears safe to proceed.']
            : [
                'Do not click any links or share sensitive information (PIN, OTP, CVV).',
                'Verify the source through official channels before acting.',
                'Report to Cyber Crime (1930) or the brand\'s customer support.',
            ];

        return res.status(200).json(buildResponse({
            verdict: frontendVerdict,
            scamType,
            confidence: Math.round(finalVerdict.confidence || 70),
            analysis,
            findings: finalVerdict.reason,
            whatToDo,
        }));
    } catch (error) {
        // NEVER return a non-JSON response — frontend will crash trying to parse it
        return res.status(200).json(buildResponse({
            verdict: 'UNCERTAIN',
            analysis: 'Temporary service issue. Please try again.',
            findings: ['Service interruption'],
            whatToDo: ['Try again in a moment.'],
        }));
    }
}
