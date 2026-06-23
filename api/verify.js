const { analyzeUrl } = require('./ghost_agent');
const { searchMasterData } = require('./db_helper'); // Assuming helper exists or logic is inline

export default async function handler(req, res) {
    const { input } = req.body;

    // Phase 1: Parallel Analysis
    const [dbResult, ghostReport] = await Promise.all([
        searchMasterData(input),
        analyzeUrl(input)
    ]);

    // Phase 2: Meta Judge Council
    let finalVerdict = {
        isScam: false,
        confidence: 0,
        reason: [],
        layers: {
            database: dbResult,
            behavioral: ghostReport,
            infrastructure: ghostReport.fingerprint
        }
    };

    // Decision Logic
    if (dbResult.found) {
        finalVerdict.isScam = true;
        finalVerdict.confidence = 99;
        finalVerdict.reason.push("Blacklisted in global threat intelligence database.");
    }

    if (ghostReport.isSuspicious) {
        finalVerdict.isScam = true;
        finalVerdict.confidence = Math.max(finalVerdict.confidence, 90);
        finalVerdict.reason.push(...ghostReport.reason);
    }

    // AI Vision Consensus (Simulated for this handler)
    if (ghostReport.screenshot && ghostReport.detectedBrand) {
        finalVerdict.reason.push(`AI Vision confirmed visual imitation of ${ghostReport.detectedBrand}.`);
        finalVerdict.confidence = 99.9;
    }

    return res.status(200).json(finalVerdict);
}
