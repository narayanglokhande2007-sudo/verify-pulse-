// tests/enterprise_gauntlet_450_social_engineering_nlp.mjs
// ============================================================================
// VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #4
// Module: Multi-Lingual Social Engineering & Intent Forensics Engine
// File Under Test: lib/intent_forensics.js (Direct NLP & Intent Analysis)
// Scope: Clean Legitimate SMS (100), Fake Loan & Advance Fee (100),
//        Digital Arrest & Authority Extortion (100), Electricity & Utility Disconnection (75),
//        Reverse UPI PIN, Remote Access & Multi-Lingual (75)
// Total Cases: 450 Adversarial Scenarios
// Objective: Stress-test intent engine to uncover real blindspots & edge failures
// ============================================================================

import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { analyzeIntentForensics } from '../lib/intent_forensics.js';

async function executeHardestGauntlet() {
    console.log('========================================================================');
    console.log('   VERIFYPULSE 450-CASE HARDEST ADVERSARIAL GAUNTLET: FEATURE #4        ');
    console.log('   Module: Multi-Lingual Social Engineering & Intent Forensics Engine   ');
    console.log('   Target: Expose Blindspots, Edge Cases & Real-World Failures          ');
    console.log('   Total Cases: 450 Extreme Adversarial Scenarios                       ');
    console.log('========================================================================\n');

    const latencies = [];
    let passedCount = 0;
    let failedCount = 0;
    const failures = [];

    function recordResult(id, category, description, passed, errorDetail = '') {
        if (passed) {
            passedCount++;
        } else {
            failedCount++;
            failures.push({ id, category, description, error: errorDetail });
        }
    }

    // ========================================================================
    // CATEGORY 1: CLEAN LEGITIMATE COMMUNICATIONS (100 CASES)
    // Target: ZERO False Positives! (highRisk must be FALSE, score < 40)
    // Even if message mentions OTP, Bank, EMI, or Cyber Safety advice!
    // ========================================================================
    console.log('--- [Category 1/5] Clean Legitimate Indian Communications (100 Cases) ---');

    const cleanTemplates = [
        'Dear Customer, your OTP for HDFC NetBanking login is 849201. Do not share this OTP with anyone, including bank staff.',
        'Dear SBI User, your A/c ending 4589 has been debited by Rs 3,450.00 on 24-Oct towards EMI. Available balance: Rs 42,100.',
        'ICICI Bank: Rs 55,000.00 credited to your Account **1029 towards salary for October 2026. Info: SAL/INFOSYS.',
        'KreditBee Loan Alert: Your EMI payment of Rs 1,890 is due on 28th Oct. Pay securely via the official KreditBee app.',
        'Axis Bank Alert: Your Credit Card ending 9012 payment of Rs 12,400 has been received successfully. Thank you.',
        'Cyber Safety Advisory from Delhi Police: Never share your UPI PIN or OTP to receive money. Stay alert, stay safe.',
        'RBI Kehta Hai: Do not click on unknown links or download apps from unverified sources. Report fraud at 1930.',
        'Airtel Update: Your unlimited 5G recharge of Rs 299 was successful. Valid for 28 days with 1.5GB/day.',
        'Swiggy Order #8921: Your delivery partner Rahul is arriving in 8 minutes. Enjoy your meal!',
        'Indian Railways (IRCTC): PNR 2451982734 confirmed for Train 12951 Mumbai Rajdhani. Coach B2 Berth 34.'
    ];

    for (let i = 0; i < 100; i++) {
        const text = `${cleanTemplates[i % cleanTemplates.length]} [Ref: VP-CLEAN-${i + 1}]`;
        const t0 = performance.now();
        const res = analyzeIntentForensics(text);
        const elapsed = performance.now() - t0;
        latencies.push(elapsed);

        const isClean = !res.highRisk && res.score < 40;
        recordResult(
            `CLEAN-${i + 1}`,
            'Clean Legitimate',
            `Legitimate Message #${i + 1}`,
            isClean,
            isClean ? '' : `False positive alarm! Flagged with score ${res.score}, signals: ${res.signals.join(', ')}`
        );
    }

    // ========================================================================
    // CATEGORY 2: FAKE LOAN APPROVAL & ADVANCE FEE EXTORTION (100 CASES)
    // Target: highRisk must be TRUE (score >= 40)
    // Includes NBFCs (KreditBee, Cashe, Navi, Kissht, PaySense, Bajaj)
    // And scams with OR without untrusted contact mentions (WhatsApp/Telegram)!
    // ========================================================================
    console.log('--- [Category 2/5] Fake Loan Approval & Advance Fee Scams (100 Cases) ---');

    const loanScamTemplates = [
        'Dear customer, your pre-approved loan of Rs 2,50,000 from KreditBee is ready for disbursement. Pay Rs 1,499 processing fee to activate.',
        'Cashe Instant Loan: Congratulations! Rs 1,80,000 sanctioned. Deposit refundable insurance fee Rs 999 to bank account immediately.',
        'Navi Finserv Loan Alert: Loan Rs 5,00,000 approved at 2% interest. Transfer file verification fee Rs 2,500 on WhatsApp 9876543210.',
        'Kissht Quick Loan: Your instant credit of Rs 75,000 is on hold. Pay Rs 499 stamp duty fee immediately to receive disbursement.',
        'Bajaj Finance Alert: Pre-approved personal loan Rs 3,00,000. Contact loan manager on Telegram @bajaj_officer and pay processing fee Rs 1,200.',
        'PaySense Micro Loan: Loan approved. Submit processing deposit Rs 1,999 to release funds into your bank account today.',
        'Tata Capital Pre-Approved Loan: Disbursal pending. Pay statutory verification charge of Rs 850 via UPI to release Rs 4,00,000 loan.',
        'Piramal Finance: Your Rs 3,50,000 loan is approved. Pay Rs 1,299 processing fee now or loan offer will expire in 2 hours.',
        'Muthoot Gold Loan Online: Instant sanction Rs 1,00,000. Transfer Rs 750 documentation fee to Telegram executive to release funds.',
        'Shriram Finance: Loan sanctioned Rs 2,00,000. Pay Rs 999 activation fee immediately to disburse money into account.'
    ];

    for (let i = 0; i < 100; i++) {
        const text = `${loanScamTemplates[i % loanScamTemplates.length]} [Case #${i + 1}]`;
        const t0 = performance.now();
        const res = analyzeIntentForensics(text);
        const elapsed = performance.now() - t0;
        latencies.push(elapsed);

        const detected = res.highRisk && res.score >= 40;
        recordResult(
            `LOAN-SCAM-${i + 1}`,
            'Loan Advance Fee',
            `Loan Scam #${i + 1}`,
            detected,
            detected ? '' : `Missed loan advance fee scam! Score: ${res.score}, signals: ${res.signals.join(', ')}`
        );
    }

    // ========================================================================
    // CATEGORY 3: DIGITAL ARREST, POLICE, ED & AUTHORITY EXTORTION (100 CASES)
    // Target: highRisk must be TRUE (score >= 40)
    // Includes CBI, Enforcement Directorate (ED), Narcotics (NCB), Cyber Cell, TRAI
    // ========================================================================
    console.log('--- [Category 3/5] Digital Arrest & Authority Extortion (100 Cases) ---');

    const authorityTemplates = [
        'CBI Cyber Crime Notice: An arrest warrant has been issued in your name for illegal money laundering. Join video call immediately or police will arrest you.',
        'Enforcement Directorate (ED) Alert: Illegal transactions detected in your name. Pay Rs 45,000 security deposit immediately to avoid asset freezing.',
        'Narcotics Control Bureau (NCB): A suspicious parcel with drugs was seized at Mumbai Customs in your name. Join WhatsApp video call immediately for digital arrest.',
        'Cyber Police Headquarter: Non-bailable arrest warrant issued. Transfer Rs 25,000 verification penalty immediately to avoid police custody.',
        'TRAI Telecom Warning: All mobile numbers under your Aadhaar will be disconnected within 2 hours by court order. Call nodal officer on WhatsApp now.',
        'Mumbai Police Crime Branch: You are placed under Digital Arrest. Do not disconnect Skype call. Pay Rs 50,000 court clearance fee to clear your name.',
        'Income Tax Department Notice: Penalty notice issued under Section 148. Pay Rs 15,000 immediately via UPI to cancel tax arrest warrant.',
        'Customs Department IGI Airport: High value foreign consignment held in your name. Pay customs duty clearance fee Rs 18,500 to avoid arrest.',
        'Supreme Court Legal Summon: You are summoned for financial fraud investigation. Contact compliance officer on Telegram to settle penalty.',
        'Delhi Cyber Crime Cell: Extortion complaint filed against your bank account. Transfer Rs 30,000 dispute deposit immediately to unfreeze.'
    ];

    for (let i = 0; i < 100; i++) {
        const text = `${authorityTemplates[i % authorityTemplates.length]} [Incident #${i + 1}]`;
        const t0 = performance.now();
        const res = analyzeIntentForensics(text);
        const elapsed = performance.now() - t0;
        latencies.push(elapsed);

        const detected = res.highRisk && res.score >= 40;
        recordResult(
            `AUTHORITY-SCAM-${i + 1}`,
            'Authority Extortion',
            `Digital Arrest / Authority Scam #${i + 1}`,
            detected,
            detected ? '' : `Missed authority extortion scam! Score: ${res.score}, signals: ${res.signals.join(', ')}`
        );
    }

    // ========================================================================
    // CATEGORY 4: ELECTRICITY BILL & UTILITY DISCONNECTION SCAMS (75 CASES)
    // Target: highRisk must be TRUE (score >= 40)
    // Highly prevalent Indian electricity power cut fraud
    // ========================================================================
    console.log('--- [Category 4/5] Electricity & Utility Disconnection Scams (75 Cases) ---');

    const electricityTemplates = [
        'Dear Consumer, your electricity power connection will be disconnected tonight at 9:30 PM from electricity office because previous month bill was not updated. Call electricity officer immediately on WhatsApp 9876501234.',
        'Bijli Vibhag Alert: Dear Consumer, your power supply will be blocked today within 2 hours due to unpaid bill. Pay Rs 450 bill update fee to avoid disconnection.',
        'MSEDCL Notice: Power disconnection order initiated for meter #48291. Contact power sub-station officer immediately on WhatsApp to update payment.',
        'BESCOM Bangalore: Dear consumer, electricity will be disconnected tonight at 10 PM. Contact electricity officer on 9988776655 and pay bill verification fee.',
        'UPPCL Alert: Your electricity meter will be disconnected today. Pay Rs 250 update charge on WhatsApp 9123456789 immediately to avoid blackout.',
        'TPDDL Delhi: Electricity supply suspension notice. Dear consumer, clear your bill today or power will be disconnected at 9:30 PM. Call helpline on WhatsApp.'
    ];

    for (let i = 0; i < 75; i++) {
        const text = `${electricityTemplates[i % electricityTemplates.length]} [Meter Ref #${i + 1}]`;
        const t0 = performance.now();
        const res = analyzeIntentForensics(text);
        const elapsed = performance.now() - t0;
        latencies.push(elapsed);

        const detected = res.highRisk && res.score >= 40;
        recordResult(
            `POWER-SCAM-${i + 1}`,
            'Electricity Scam',
            `Electricity Disconnection Scam #${i + 1}`,
            detected,
            detected ? '' : `Missed electricity disconnection scam! Score: ${res.score}, signals: ${res.signals.join(', ')}`
        );
    }

    // ========================================================================
    // CATEGORY 5: REVERSE UPI PIN, REMOTE ACCESS & MULTI-LINGUAL (75 CASES)
    // Target: highRisk must be TRUE (score >= 40)
    // Reverse UPI PIN scams, AnyDesk/TeamViewer traps, Hindi, Bengali, Tamil, Telugu
    // ========================================================================
    console.log('--- [Category 5/5] Reverse UPI PIN, Screen Share & Regional Languages (75 Cases) ---');

    const complexTemplates = [
        // Reverse UPI PIN Deception
        'PhonePe Reward: Congratulations! You won Rs 4,999 cashback. Scan the QR code and enter your UPI PIN to receive money in your bank account.',
        'Google Pay Scratch Card: Rs 2,500 prize waiting! Scan this QR code now and approve the collect request to get cashback.',
        'Paytm Refund: Rs 3,000 refund approved for failed order. Scan the QR code and enter your UPI PIN immediately to claim your refund.',
        
        // Remote Access / AnyDesk Trap
        'SBI Customer Support: Your YONO account is suspended. Download AnyDesk from Play Store and share screen with customer agent to reactivate immediately.',
        'HDFC Bank Alert: NetBanking blocked due to pending PAN KYC. Install QuickSupport app and share your screen to complete biometric verification.',
        
        // Multi-Lingual Traps (Hindi, Bengali, Telugu, Tamil)
        'साइबर पुलिस सूचना: आपके बैंक खाते से अवैध मनी लॉन्ड्रिंग हुई है। तुरंत ₹25,000 शुल्क जमा करें नहीं तो आज गिरफ्तारी होगी।',
        'प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा। तुरंत व्हाट्सएप पर संपर्क करें और बिल अपडेट करें।',
        'অভিনন্দন! আপনি PhonePe থেকে ₹৫,০০০ পুরস্কার পেয়েছেন। টাকা পেতে QR কোড স্ক্যান করুন এবং আপনার UPI PIN দিন।',
        'విద్యుత్ బిల్లు హెచ్చరిక: ఈ రాత్రి 9:30 గంటలకు మీ విద్యుత్ సరఫరా నిలిపివేయబడుతుంది. వెంటనే వాట్సాప్‌లో సంప్రదించండి.',
        'காவல் துறை எச்சரிக்கை: உங்கள் வங்கிக் கணக்கு முடக்கப்பட்டுள்ளது. உடனடியாக அபராதம் ₹20,000 செலுத்தவும் இல்லை என்றால் கைது செய்யப்படுவீர்கள்.'
    ];

    for (let i = 0; i < 75; i++) {
        const text = `${complexTemplates[i % complexTemplates.length]} [Code #${i + 1}]`;
        const t0 = performance.now();
        const res = analyzeIntentForensics(text);
        const elapsed = performance.now() - t0;
        latencies.push(elapsed);

        const detected = res.highRisk && res.score >= 40;
        recordResult(
            `MULTI-SCAM-${i + 1}`,
            'Multi-Lingual & Traps',
            `Multi-Lingual / Reverse UPI Scam #${i + 1}`,
            detected,
            detected ? '' : `Missed complex/regional scam! Score: ${res.score}, signals: ${res.signals.join(', ')}`
        );
    }

    // ========================================================================
    // FINAL GAUNTLET SUMMARY AUDIT
    // ========================================================================
    console.log('\n========================================================================');
    console.log('   FEATURE #4 HARDEST GAUNTLET SUMMARY AUDIT METRICS                    ');
    console.log('========================================================================');
    console.log(`Total Cases Tested:      ${passedCount + failedCount}`);
    console.log(`Total Passed:            ${passedCount} ✅`);
    console.log(`Total Failed:            ${failedCount} ❌`);
    console.log(`Success Rate:            ${((passedCount / (passedCount + failedCount)) * 100).toFixed(2)}%`);

    latencies.sort((a, b) => a - b);
    const min = latencies[0].toFixed(3);
    const avg = (latencies.reduce((sum, v) => sum + v, 0) / latencies.length).toFixed(3);
    const p95 = latencies[Math.floor(latencies.length * 0.95)].toFixed(3);
    const p99 = latencies[Math.floor(latencies.length * 0.99)].toFixed(3);
    const max = latencies[latencies.length - 1].toFixed(3);

    console.log('\n--- LATENCY BENCHMARK ---');
    console.log(`Min Latency: ${min} ms | Avg Latency: ${avg} ms | Max Latency: ${max} ms`);

    if (failures.length > 0) {
        console.log(`\n⚠️  EXPOSED SYSTEM BLINDSPOTS (${failures.length} Real Failures Found):`);
        // Group failures by category
        const categorized = {};
        failures.forEach(f => {
            if (!categorized[f.category]) categorized[f.category] = [];
            categorized[f.category].push(f);
        });

        for (const [cat, items] of Object.entries(categorized)) {
            console.log(`\n[${cat}] -> ${items.length} Failed Cases:`);
            items.slice(0, 3).forEach(item => {
                console.log(`  * [${item.id}] ${item.description}: ${item.error}`);
            });
            if (items.length > 3) {
                console.log(`    ... and ${items.length - 3} more cases in this category.`);
            }
        }
    } else {
        console.log('\n🎉 ALL 450 HARDEST TEST CASES PASSED!');
    }
    console.log('========================================================================\n');
}

executeHardestGauntlet().catch(err => {
    console.error('Gauntlet runner fatal error:', err);
    process.exit(1);
});
