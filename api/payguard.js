// api/payguard.js
// VerifyPulse Tier 3: Real-Time Transaction Firewall (PayGuard)
// Deep Integration API for NBFCs and Payment Gateways to intercept payments to scammers.

import { validateB2bApiKey } from '../lib/security_controls.js';
import { querySyndicateGraph } from '../lib/syndicate_graph.js';
import crypto from 'node:crypto';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    // 1. Validate Tier Authentication (Tier 2 Pro & Tier 3 Ultra feature)
    const authResult = validateB2bApiKey(req);
    if (!authResult.valid) {
        return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Valid B2B API key required.' });
    }
    
    // Tier check: Available to Pro (Tier 2) and Ultra (Tier 3)
    if (authResult.tier < 2) {
        return res.status(403).json({ 
            error: 'UPGRADE_REQUIRED', 
            message: 'VerifyPulse PayGuard & Scam Syndicate Graph is available on Tier 2 (Pro) or higher.' 
        });
    }

    const { transactionId, amount, receiverUpi, receiverPhone, receiverIfsc } = req.body;
    
    if (!transactionId || (!receiverUpi && !receiverPhone && !receiverIfsc)) {
        return res.status(400).json({ 
            error: 'MISSING_DATA', 
            message: 'transactionId and at least one receiver identifier (UPI/Phone/IFSC) is required.' 
        });
    }

    // 2. Real-Time Risk Scoring Engine
    let riskScore = 0;
    let flags = [];
    let syndicateDetails = null;
    
    // A. UPI Handle Heuristics
    if (receiverUpi) {
        const upi = receiverUpi.toLowerCase();
        if (upi.includes('kyc') || upi.includes('update') || upi.includes('refund') || upi.includes('cashback') || upi.includes('support')) {
            riskScore += 70;
            flags.push('SUSPICIOUS_MULE_UPI_PATTERN');
        }
        if (/[a-z]{2,4}\d{5,8}@[a-z]+/.test(upi)) {
            riskScore += 30;
            flags.push('ALGORITHMIC_GENERATED_UPI');
        }
    }

    // B. Phone Number Telecom Heuristics (SIM Check Simulation)
    if (receiverPhone) {
        if (receiverPhone.startsWith('+9170') || receiverPhone.startsWith('+9160')) {
            riskScore += 15;
            flags.push('NEW_SIM_BLOCK_DETECTED');
        }
    }

    // C. Psychological Fraud Amount Velocity
    if (amount) {
        const numAmount = Number(amount);
        if (numAmount === 9999 || numAmount === 19999 || numAmount === 4999 || numAmount === 999) {
            riskScore += 25;
            flags.push('PSYCHOLOGICAL_SCAM_AMOUNT');
        }
    }

    // D. Cross-Reference with Scam Syndicate Graph (Threat Intelligence)
    const graphMatch = await querySyndicateGraph({
        upi: receiverUpi,
        phone: receiverPhone,
        ifsc: receiverIfsc
    });

    if (graphMatch.found) {
        riskScore = Math.max(riskScore, 95);
        flags.push('SCAM_SYNDICATE_GRAPH_MATCH');
        syndicateDetails = {
            clusterId: graphMatch.clusterId,
            category: graphMatch.category,
            matchedNode: graphMatch.matchedNode,
            connectedNodes: graphMatch.connectedNodes,
            confidence: graphMatch.confidence
        };
    }

    // 3. Verdict Calculation
    riskScore = Math.min(riskScore, 100);
    let action = 'ALLOW';
    
    if (riskScore >= 75) {
        action = 'BLOCK';
    } else if (riskScore >= 45) {
        action = 'REVIEW';
    }

    // 4. Respond in milliseconds to the NBFC Payment Gateway
    return res.status(200).json({
        transactionId,
        evaluatedAt: new Date().toISOString(),
        riskScore,
        action,
        flags,
        syndicate: syndicateDetails,
        recommendation: action === 'BLOCK' ? 'Halt transaction immediately. High probability of mule account routing.' : 
                        action === 'REVIEW' ? 'Introduce friction. Require biometric or voice confirmation from sender.' : 
                        'Proceed with standard gateway fraud checks.'
    });
}