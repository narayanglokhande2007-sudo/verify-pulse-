const { analyzeUrl } = require('./ghost_agent_pooled');

// Simple in-memory rate limiter
const requestCounts = {};
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 100; // Max 100 requests per 15 minutes per IP

const { searchMasterData } = require(\'./db_helper\');

module.exports = async function handler(req, res) {
    const clientIp = req.headers[\'x-forwarded-for\'] || req.connection.remoteAddress;

    if (!requestCounts[clientIp]) {
        requestCounts[clientIp] = {
            count: 0,
            lastReset: Date.now()
        };
    }

    const now = Date.now();
    if (now - requestCounts[clientIp].lastReset > WINDOW_MS) {
        requestCounts[clientIp].count = 0;
        requestCounts[clientIp].lastReset = now;
    }

    if (requestCounts[clientIp].count >= MAX_REQUESTS) {
        return res.status(429).json({ error: "Too many requests from this IP, please try again later." });
    }

    requestCounts[clientIp].count++;

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
            infrastructure: ghostReport.fingerprint,
            ghostAgentConfidence: ghostReport.confidence // Include Ghost Agent's confidence
        }
    };

    // Decision Logic
        // Decision Logic - Enhanced Meta Judge Consensus
        let totalConfidence = 0;
        let contributingFactors = [];

        // Initialize isScam based on initial high confidence factors
        if (dbResult.found) {
            finalVerdict.isScam = true;
            totalConfidence += 50; // High base confidence from database match
            contributingFactors.push("Blacklisted in global threat intelligence database.");
        }

        if (ghostReport.isSuspicious) {
            // isScam will be determined by final confidence score
            // finalVerdict.isScam = true;
            totalConfidence += ghostReport.confidence * 0.5; // Ghost Agent's confidence contributes significantly
            contributingFactors.push(...ghostReport.reason);
        }

        // AI Vision Consensus (Simulated for this handler) - now integrated into Ghost Agent's confidence
        if (ghostReport.detectedBrand && ghostReport.confidence >= 80) { // If Ghost Agent is highly confident about brand imitation
            contributingFactors.push(`AI Vision confirmed strong visual/text imitation of ${ghostReport.detectedBrand}.`);
            totalConfidence += 20; // Additional confidence for strong visual confirmation
        }

        // Final Confidence Calculation
        finalVerdict.confidence = Math.min(100, Math.round(totalConfidence));
        if (finalVerdict.confidence >= 70) { // Threshold for considering it a scam
            finalVerdict.isScam = true;
        } else {
            finalVerdict.isScam = false; // Reset if confidence is low
        }
        finalVerdict.reason = Array.from(new Set(contributingFactors)); // Remove duplicate reasons


    return res.status(200).json(finalVerdict);
}

// Simulated modification by Minimax AI
