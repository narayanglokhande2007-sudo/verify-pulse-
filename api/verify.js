// Defensive dynamic imports — if a module fails to load (e.g. missing optional deps on Vercel),
// fall back to a stub so the handler ALWAYS returns valid JSON.
let analyzeUrl;
try {
    const ghostAgentModule = await import('./ghost_agent');
    ({ analyzeUrl } = ghostAgentModule);
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
    const dbHelperModule = await import('./db_helper');
    ({ searchMasterData } = dbHelperModule);
} catch (e) {
    console.warn('[verify] db_helper unavailable, using stub:', e.message);
    searchMasterData = () => ({ found: false });
}

const { spawn } = await import('child_process');

// Function to call the Python brand protection script
const runBrandProtectionPython = (brandName) => {
    return new Promise((resolve, reject) => {
        const pythonProcess = spawn('python3', ['brand_protection.py', brandName]);
        let rawData = '';
        pythonProcess.stdout.on('data', (data) => { rawData += data.toString(); });
        pythonProcess.stderr.on('data', (data) => { console.error(`stderr: ${data}`); });

        pythonProcess.on('close', (code) => {
            if (code !== 0) {
                return reject(new Error(`Python script exited with code ${code}`));
            }
            try {
                resolve(JSON.parse(rawData));
            } catch (jsonErr) {
                reject(new Error('Failed to parse Python script output: ' + jsonErr.message));
            }
        });
        pythonProcess.on('error', (err) => { reject(err); });
    });
};

export default async function handler(req, res) {
    // CORS so the site (and any other clients) can call this endpoint
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Helper to detect input type
    const detectInputType = (input) => {
        // Regex for URL
        const urlRegex = new RegExp('^(https?:\\/\\/)?' + // protocol
            '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // domain name
            '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR ip (v4) address
            '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path
            '(\\?[;&a-z\\d%_.~+=-]*)?' + // query string
            '(\\#[-a-z\\d_]*)?$', 'i'); // fragment locator
        if (urlRegex.test(input)) {
            return 'URL';
        }

        // Regex for Indian Phone Number (10 digits, starting with 6,7,8,9)
        const phoneRegex = /^[6-9]\\d{9}$/;
        if (phoneRegex.test(input)) {
            return 'PHONE_NUMBER';
        }

        // Regex for UPI ID (e.g., user@bankname, 1234567890@upi)
        const upiRegex = /^[a-zA-Z0-9.\\-]+@[a-zA-Z0-9.\\-]+$/;
        if (upiRegex.test(input)) {
            return 'UPI_ID';
        }

        return 'TEXT';
    };

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

        // Phase 1: Parallel Analysis
        const inputType = detectInputType(userInput);

        let ghostAnalysisPromise;
        if (inputType === 'URL') {
            ghostAnalysisPromise = Promise.resolve(analyzeUrl(userInput)).catch(err => ({
                isSuspicious: false,
                reason: ['Behavioural analysis failed: ' + err.message],
                detectedBrand: null,
                fingerprint: {},
                errorOccurred: true,
            }));
        } else {
            // For non-URL inputs, bypass ghost_agent for now
            ghostAnalysisPromise = Promise.resolve({
                isSuspicious: false,
                reason: [`Behavioural analysis skipped for input type: ${inputType}`],
                detectedBrand: null,
                fingerprint: {},
                errorOccurred: false,
            });
        }

        // Brand Protection Analysis - only if a potential brand name is present/detectable
        let brandProtectionPromise = Promise.resolve({
            threat_found: false,
            details: 'Brand protection skipped or unavailable.'
        });
        // This is a simplistic check; a more advanced version would extract brand names from text
        if (userInput && inputType === 'TEXT') { // Only try for TEXT inputs for now, could expand
            brandProtectionPromise = runBrandProtectionPython(userInput).catch(err => {
                console.error('[verify] Brand Protection Python script failed:', err.message);
                return { threat_found: false, details: `Brand protection failed: ${err.message}` };
            });
        }

        const [dbResult, ghostReport, brandProtectionResult] = await Promise.all([
            Promise.resolve(searchMasterData(userInput)),
            ghostAnalysisPromise,
            brandProtectionPromise,
        ]);

        // Phase 2: Meta Judge Council (refined logic)
        let finalVerdict = {
            isScam: false,
            confidence: 0,
            reason: [],
            layers: {
                database: dbResult,
                behavioral: ghostReport,
                infrastructure: ghostReport.fingerprint,
                brandProtection: brandProtectionResult,
            },
        };

        // Start with a base confidence if any layer detects a potential issue
        if (dbResult.found || ghostReport.isSuspicious || brandProtectionResult.threat_found) {
            finalVerdict.confidence = 60; // Base confidence for suspicious activity
        }

        // Decision Logic (refined)
        if (dbResult.found) {
            finalVerdict.isScam = true;
            finalVerdict.confidence = Math.min(99, finalVerdict.confidence + 30); // High confidence boost for DB hit
            finalVerdict.reason.push('Blacklisted in global threat intelligence database.');
        }

        if (ghostReport.isSuspicious) {
            finalVerdict.isScam = true;
            finalVerdict.confidence = Math.min(99.9, finalVerdict.confidence + 25); // Significant confidence boost for behavioral
            finalVerdict.reason.push(...ghostReport.reason);
        }

        if (ghostReport.screenshot && ghostReport.detectedBrand) {
            finalVerdict.isScam = true; // Explicitly set to scam if AI vision confirms brand imitation
            finalVerdict.reason.push(`AI Vision confirmed visual imitation of ${ghostReport.detectedBrand}.`);
            finalVerdict.confidence = 99.9; // Very high confidence for visual confirmation
        }

        if (brandProtectionResult.threat_found) {
            finalVerdict.isScam = true;
            finalVerdict.confidence = Math.min(99, finalVerdict.confidence + 20); // Moderate confidence boost for brand protection
            finalVerdict.reason.push(`Brand Protection: ${brandProtectionResult.details}`);
        }

        // If no scam detected but confidence is low, keep it uncertain
        if (!finalVerdict.isScam && finalVerdict.confidence < 60 &&
            (ghostReport.reason.length > 0 && !ghostReport.errorOccurred)) { // Only if ghost_agent had some signals but not definitive
            finalVerdict.confidence = 50; // Revert to default uncertain confidence
        }

        // Map internal verdict -> frontend-expected format
        let frontendVerdict = 'SAFE';
        if (finalVerdict.isScam) {
            frontendVerdict = (ghostReport.detectedBrand || finalVerdict.confidence >= 95) ? 'DANGEROUS' : 'SUSPICIOUS';
        } else if (ghostReport.errorOccurred) {
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

        // Enhance analysis with system status for unavailable layers
        const systemStatus = {};
        if (ghostReport.errorOccurred) {
            systemStatus.behavioral = 'Unavailable';
            analysis += ' Behavioural analysis was unavailable due to an error.';
        } else {
            systemStatus.behavioral = 'Active';
        }

        if (dbResult.errorOccurred) { // Assuming db_helper could also return an errorOccurred flag
            systemStatus.database = 'Unavailable';
            analysis += ' Database lookup was unavailable due to an error.';
        } else {
            systemStatus.database = 'Active';
        }

        // For brand protection, assuming it always returns a result even if placeholder
        systemStatus.brandProtection = brandProtectionResult.details.includes('skipped') ? 'Skipped' : 'Active';
        if (brandProtectionResult.details.includes('failed')) {
            systemStatus.brandProtection = 'Failed';
            analysis += ` Brand protection analysis failed: ${brandProtectionResult.details.split(':')[1].trim()}.`;
        }

        // Add this systemStatus to the response
        return res.status(200).json(buildResponse({
            verdict: frontendVerdict,
            scamType,
            confidence: Math.round(finalVerdict.confidence || 70),
            analysis,
            findings: finalVerdict.reason,
            whatToDo,
            systemStatus, // New field to show layer status
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
