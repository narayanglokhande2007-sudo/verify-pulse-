// tests/enterprise_gauntlet_450_financial_mule_screening.mjs
// ============================================================================
// VERIFYPULSE 450-CASE ENTERPRISE BATTLE GAUNTLET: FEATURE #3
// Module: Pre-Disbursal Financial Forensics, Mule Screening & Syndicate Graph
// Endpoints: api/payguard.js & lib/financial_forensics.js & lib/syndicate_graph.js
// Scope: Clean Legitimate Borrowers (100), Mule UPI & Traps (100),
//        Scam Syndicate Graph (100), IFSC & Telecom Forensics (75),
//        Security, Auth, Quotas & Edge Payloads (75)
// Total Cases: 450 Cases (100% Automated Enterprise Benchmark)
// ============================================================================

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import payguardHandler from '../api/payguard.js';
import { analyzeFinancialThreats } from '../lib/financial_forensics.js';
import { querySyndicateGraph } from '../lib/syndicate_graph.js';

function hash(v) {
    return crypto.createHash('sha256').update(v).digest('hex');
}

function mockRes() {
    return {
        statusCode: 200,
        headers: {},
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        setHeader(name, val) {
            this.headers[name] = val;
            return this;
        },
        json(payload) {
            this.body = payload;
            return this;
        }
    };
}

// B2B Registry Setup
const keyTier2 = 'vp_test_tier2_pro_financial_key_888';
const keyTier1 = 'vp_test_tier1_starter_key_222';
const keyNoScope = 'vp_test_noscope_key_333';

process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
    {
        keyId: 'pro-financial-corp',
        tenantId: 'enterprise_lender_bank',
        tier: 2,
        sha256: hash(keyTier2),
        scopes: ['b2b:payguard', 'b2b:scan'],
        expiresAt: '2099-01-01T00:00:00.000Z',
        status: 'active'
    },
    {
        keyId: 'starter-financial-corp',
        tenantId: 'starter_corp',
        tier: 1,
        sha256: hash(keyTier1),
        scopes: ['b2b:scan'],
        expiresAt: '2099-01-01T00:00:00.000Z',
        status: 'active'
    },
    {
        keyId: 'noscope-financial-corp',
        tenantId: 'noscope_corp',
        tier: 2,
        sha256: hash(keyNoScope),
        scopes: ['b2b:other'],
        expiresAt: '2099-01-01T00:00:00.000Z',
        status: 'active'
    }
]);

function getProHeaders(ipSuffix = 1) {
    return {
        'x-api-key': keyTier2,
        'x-verifypulse-key-id': 'pro-financial-corp',
        'x-forwarded-for': `198.51.100.${(ipSuffix % 250) + 1}`
    };
}

async function executeGauntlet() {
    console.log('========================================================================');
    console.log('   VERIFYPULSE 450-CASE ENTERPRISE BATTLE GAUNTLET: FEATURE #3           ');
    console.log('   Module: Pre-Disbursal Mule Account & Syndicate Detection (PayGuard)   ');
    console.log('   Total Cases: 450 across 5 Critical Enterprise Categories              ');
    console.log('========================================================================\n');

    const latencies = [];
    let passedCount = 0;
    let failedCount = 0;
    const failures = [];

    async function recordTest(id, name, testFn) {
        const t0 = performance.now();
        try {
            await testFn();
            const elapsed = performance.now() - t0;
            latencies.push(elapsed);
            passedCount++;
        } catch (err) {
            const elapsed = performance.now() - t0;
            latencies.push(elapsed);
            failedCount++;
            failures.push({ id, name, error: err.message });
        }
    }

    // ========================================================================
    // CATEGORY 1: CLEAN LEGITIMATE INDIAN BORROWERS (100 CASES)
    // Target: Zero False Positives! action: ALLOW, riskScore: 0, flags: []
    // ========================================================================
    console.log('--- [Category 1/5] Clean Legitimate Indian Borrowers (100 Cases) ---');

    const genuineBanks = [
        { bank: 'HDFC', ifsc: 'HDFC0000128', handle: 'okhdfcbank' },
        { bank: 'SBI', ifsc: 'SBIN0000456', handle: 'oksbi' },
        { bank: 'ICICI', ifsc: 'ICIC0001020', handle: 'okicici' },
        { bank: 'Axis', ifsc: 'UTIB0000005', handle: 'okaxis' },
        { bank: 'Kotak', ifsc: 'KKBK0000123', handle: 'kotak' },
        { bank: 'PNB', ifsc: 'PUNB0123400', handle: 'pnb' },
        { bank: 'Bank of Baroda', ifsc: 'BARB0MUMBAI', handle: 'barodampay' },
        { bank: 'Canara', ifsc: 'CNRB0000100', handle: 'canarabank' },
        { bank: 'IDFC First', ifsc: 'IDFB0040101', handle: 'idfcbank' },
        { bank: 'IndusInd', ifsc: 'INDB0000001', handle: 'indus' }
    ];

    const genuineNames = [
        'rahul.sharma', 'priya.nair', 'amit.verma', 'sneha.patel', 'vikram.singh',
        'ananya.iyer', 'rohit.gupta', 'pooja.deshmukh', 'suresh.reddy', 'deepika.sen'
    ];

    for (let i = 0; i < 100; i++) {
        const bankItem = genuineBanks[i % genuineBanks.length];
        const nameItem = genuineNames[Math.floor(i / 10) % genuineNames.length];
        const cleanUpi = `${nameItem}${i + 1}@${bankItem.handle}`;
        const cleanPhone = `9820${String(100000 + i).slice(-6)}`;
        const cleanAmount = (5000 + (i * 2500)); // Standard legitimate loan amounts (not psychological)

        await recordTest(`CLEAN-${i + 1}`, `Clean Borrower Loan Disbursal #${i + 1} (${bankItem.bank})`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 1),
                body: {
                    transactionId: `TXN-GENUINE-LOAN-${1000 + i}`,
                    amount: cleanAmount,
                    receiverUpi: cleanUpi,
                    receiverPhone: cleanPhone,
                    receiverIfsc: bankItem.ifsc
                }
            }, res);

            assert.equal(res.statusCode, 200, `Expected HTTP 200 for ${cleanUpi}`);
            assert.equal(res.body.action, 'ALLOW', `Clean transaction must be ALLOW, got ${res.body.action}`);
            assert.equal(res.body.riskScore, 0, `Risk score should be 0, got ${res.body.riskScore}`);
            assert.deepEqual(res.body.flags, [], 'Clean transaction should have zero flags');
            assert.equal(res.body.syndicate, null, 'Clean transaction must not match syndicate');
        });
    }

    // ========================================================================
    // CATEGORY 2: MULE UPI ACCOUNTS & SOCIAL ENGINEERING TRAPS (100 CASES)
    // Target: Flags triggered, riskScore >= 70, action: BLOCK or REVIEW
    // ========================================================================
    console.log('--- [Category 2/5] Mule UPI Accounts & Phishing Traps (100 Cases) ---');

    const muleKeywords = [
        'kyc.approval', 'update.pan', 'refund.desk', 'cashback.reward', 'support.agent',
        'disbursal.fee', 'processing.charge', 'approval.fast', 'lottery.win', 'customs.clearance',
        'cbi.settlement', 'police.cyber', 'task.daily', 'telegram.earn', 'crypto.withdraw',
        'binance.usdt', 'doublemoney.vip', 'bonus.claim', 'instantloan.pay', 'settlement.desk'
    ];

    const upiProviders = ['ybl', 'paytm', 'okaxis', 'okhdfcbank', 'okicici'];

    for (let i = 0; i < 100; i++) {
        const kw = muleKeywords[i % muleKeywords.length];
        const prov = upiProviders[i % upiProviders.length];
        const muleUpi = `${kw}${i + 1}@${prov}`;
        const psychAmount = [999, 1999, 4999, 9999, 19999, 49999][i % 6]; // Classic scam amounts

        await recordTest(`MULE-UPI-${i + 1}`, `Mule UPI Impersonation #${i + 1} (${kw})`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 101),
                body: {
                    transactionId: `TXN-MULE-TRAP-${2000 + i}`,
                    amount: psychAmount,
                    receiverUpi: muleUpi,
                    receiverPhone: `9988776655`,
                    receiverIfsc: 'HDFC0000128'
                }
            }, res);

            assert.equal(res.statusCode, 200, `Expected HTTP 200 for ${muleUpi}`);
            assert.ok(
                res.body.action === 'BLOCK' || res.body.action === 'REVIEW',
                `Expected BLOCK or REVIEW for mule UPI, got ${res.body.action}`
            );
            assert.ok(res.body.riskScore >= 70, `Expected riskScore >= 70, got ${res.body.riskScore}`);
            assert.ok(res.body.flags.includes('SUSPICIOUS_MULE_UPI_PATTERN'), 'Should detect SUSPICIOUS_MULE_UPI_PATTERN');
            assert.ok(res.body.flags.includes('PSYCHOLOGICAL_SCAM_AMOUNT'), 'Should detect PSYCHOLOGICAL_SCAM_AMOUNT');
        });
    }

    // ========================================================================
    // CATEGORY 3: SCAM SYNDICATE GRAPH CORRELATION (100 CASES)
    // Target: Multi-node cluster matching, flags: SCAM_SYNDICATE_GRAPH_MATCH, riskScore: >= 95
    // ========================================================================
    console.log('--- [Category 3/5] Scam Syndicate Graph Correlation (100 Cases) ---');

    const syndicateSeeds = [
        { node: 'cbi.cybercell.verify@ybl', clusterId: 'syn-dl-arrest-01', cat: 'Digital Arrest' },
        { node: 'mha.cyberdesk@icici', clusterId: 'syn-dl-arrest-01', cat: 'Digital Arrest' },
        { node: '9876501234', clusterId: 'syn-dl-arrest-01', cat: 'Digital Arrest' },
        { node: '+919876501235', clusterId: 'syn-dl-arrest-01', cat: 'Digital Arrest' },
        { node: 'SBIN0MULE01', clusterId: 'syn-dl-arrest-01', cat: 'Digital Arrest' },

        { node: 'discom.billupdate@okaxis', clusterId: 'syn-elec-bill-02', cat: 'Electricity Bill' },
        { node: 'powerpay.officer@oksbi', clusterId: 'syn-elec-bill-02', cat: 'Electricity Bill' },
        { node: '7001234567', clusterId: 'syn-elec-bill-02', cat: 'Electricity Bill' },
        { node: '+916009876543', clusterId: 'syn-elec-bill-02', cat: 'Electricity Bill' },
        { node: 'HDFC0MULE02', clusterId: 'syn-elec-bill-02', cat: 'Electricity Bill' },

        { node: 'instantrupee.settle@paytm', clusterId: 'syn-loan-apk-03', cat: 'Loan App Extortion' },
        { node: 'fastcredit.loan@ybl', clusterId: 'syn-loan-apk-03', cat: 'Loan App Extortion' },
        { node: '8800112233', clusterId: 'syn-loan-apk-03', cat: 'Loan App Extortion' },
        { node: '+919911223344', clusterId: 'syn-loan-apk-03', cat: 'Loan App Extortion' },
        { node: 'ICIC0MULE03', clusterId: 'syn-loan-apk-03', cat: 'Loan App Extortion' },

        { node: 'sbi.yono.kyc@paytm', clusterId: 'syn-jamtara-kyc-04', cat: 'Jamtara KYC' },
        { node: 'pnb.netbanking@ybl', clusterId: 'syn-jamtara-kyc-04', cat: 'Jamtara KYC' },
        { node: '9708112233', clusterId: 'syn-jamtara-kyc-04', cat: 'Jamtara KYC' },
        { node: '+919708112234', clusterId: 'syn-jamtara-kyc-04', cat: 'Jamtara KYC' },
        { node: 'PUNB0MULE04', clusterId: 'syn-jamtara-kyc-04', cat: 'Jamtara KYC' },

        { node: 'armyofficer.deposit@okaxis', clusterId: 'syn-mewat-olx-05', cat: 'Mewat Army OLX' },
        { node: 'crpf.canteen@okhdfcbank', clusterId: 'syn-mewat-olx-05', cat: 'Mewat Army OLX' },
        { node: '9982334455', clusterId: 'syn-mewat-olx-05', cat: 'Mewat Army OLX' },
        { node: '+919982334456', clusterId: 'syn-mewat-olx-05', cat: 'Mewat Army OLX' },
        { node: 'KKBK0MULE05', clusterId: 'syn-mewat-olx-05', cat: 'Mewat Army OLX' }
    ];

    for (let i = 0; i < 100; i++) {
        const seed = syndicateSeeds[i % syndicateSeeds.length];
        const isUpi = seed.node.includes('@');
        const isIfsc = /^[A-Z]{4}0[A-Z0-9]{6}$/.test(seed.node);
        const isPhone = !isUpi && !isIfsc;

        const payload = {
            transactionId: `TXN-SYNDICATE-TEST-${3000 + i}`,
            amount: 25000,
            receiverUpi: isUpi ? seed.node : 'normal.user@okhdfcbank',
            receiverPhone: isPhone ? seed.node : '9820123456',
            receiverIfsc: isIfsc ? seed.node : 'HDFC0000128'
        };

        await recordTest(`SYNDICATE-${i + 1}`, `Scam Syndicate Match #${i + 1} (${seed.cat})`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 201),
                body: payload
            }, res);

            assert.equal(res.statusCode, 200);
            assert.equal(res.body.action, 'BLOCK', 'Syndicate match must be BLOCKED');
            assert.ok(res.body.riskScore >= 95, `Risk score must be >= 95, got ${res.body.riskScore}`);
            assert.ok(res.body.flags.includes('SCAM_SYNDICATE_GRAPH_MATCH'), 'Must flag SCAM_SYNDICATE_GRAPH_MATCH');
            assert.equal(res.body.syndicate?.clusterId, seed.clusterId, `ClusterId must be ${seed.clusterId}`);
            assert.ok(res.body.syndicate?.confidence >= 95, 'Syndicate confidence must be >= 95');
        });
    }

    // ========================================================================
    // CATEGORY 4: BANKING IFSC & TELECOM NUMBER FORENSICS (75 CASES)
    // Target: Malformed IFSC, High-Risk Mule IFSC, Malformed & Burner Phone detection
    // ========================================================================
    console.log('--- [Category 4/5] Banking IFSC & Telecom Forensics (75 Cases) ---');

    // 25 Malformed IFSCs
    const malformedIfscs = [
        'HDFC1234567', 'sbi0001234', 'ICIC00000', 'UTIB000000001', 'KKBK-001234',
        'PUNB0000', 'BARB12345', 'CNRB', '12345678901', 'HDFC000012@',
        'HDFC 00001', 'SBIN00004567', 'ICIC00001A!', 'PUNB0_1234', 'AXIS0001234'
    ];
    for (let i = 0; i < 25; i++) {
        const ifsc = malformedIfscs[i % malformedIfscs.length];
        await recordTest(`IFSC-MALFORMED-${i + 1}`, `Reject malformed IFSC (${ifsc})`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 301),
                body: {
                    transactionId: `TXN-IFSC-MAL-${i}`,
                    receiverIfsc: ifsc,
                    receiverUpi: 'valid.user@okhdfcbank'
                }
            }, res);

            assert.equal(res.statusCode, 200);
            assert.ok(res.body.flags.includes('INVALID_IFSC_FORMAT'), `Expected INVALID_IFSC_FORMAT for ${ifsc}`);
            assert.ok(res.body.riskScore >= 35);
        });
    }

    // 25 High-Risk Mule IFSCs
    const highRiskIfscs = [
        'PYTM0123456', 'UTBI0MULE01', 'FAKE0001234', 'SBIN0MULE01', 'HDFC0MULE02',
        'ICIC0MULE03', 'PUNB0MULE04', 'KKBK0MULE05', 'YESB0MULE06', 'UTIB0MULE07'
    ];
    for (let i = 0; i < 25; i++) {
        const ifsc = highRiskIfscs[i % highRiskIfscs.length];
        await recordTest(`IFSC-MULE-${i + 1}`, `Flag high-risk mule branch IFSC (${ifsc})`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 326),
                body: {
                    transactionId: `TXN-IFSC-MULE-${i}`,
                    receiverIfsc: ifsc,
                    receiverUpi: 'normal.customer@okhdfcbank'
                }
            }, res);

            assert.equal(res.statusCode, 200);
            assert.ok(
                res.body.flags.includes('HIGH_RISK_MULE_IFSC') || res.body.flags.includes('SCAM_SYNDICATE_GRAPH_MATCH'),
                `Expected HIGH_RISK_MULE_IFSC for ${ifsc}`
            );
            assert.ok(res.body.riskScore >= 45);
        });
    }

    // 25 Malformed & Burner Phone Numbers
    const badPhones = [
        { p: '12345', desc: 'Too short (5 digits)' },
        { p: '987654321012345', desc: 'Too long (15 digits)' },
        { p: '5123456789', desc: 'Invalid starting digit 5' },
        { p: '0123456789', desc: 'Invalid starting digit 0' },
        { p: '+917012345678', desc: 'Burner SIM block 70' },
        { p: '+916098765432', desc: 'Burner SIM block 60' },
        { p: 'abcdefghij', desc: 'Non-numeric string' }
    ];
    for (let i = 0; i < 25; i++) {
        const phoneItem = badPhones[i % badPhones.length];
        await recordTest(`PHONE-FORENSIC-${i + 1}`, `Telecom validation: ${phoneItem.desc}`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 351),
                body: {
                    transactionId: `TXN-PHONE-${i}`,
                    receiverPhone: phoneItem.p,
                    receiverUpi: 'regular.borrower@okaxis'
                }
            }, res);

            assert.equal(res.statusCode, 200);
            assert.ok(
                res.body.flags.includes('INVALID_PHONE_FORMAT') || res.body.flags.includes('NEW_SIM_BLOCK_DETECTED') || res.body.flags.includes('SCAM_SYNDICATE_GRAPH_MATCH'),
                `Should flag phone anomaly for ${phoneItem.p}`
            );
        });
    }

    // ========================================================================
    // CATEGORY 5: SECURITY, AUTH, QUOTAS & EDGE PAYLOAD BOUNDARIES (75 CASES)
    // Target: 401 unauth, 403 scope/tier, 400 missing data, negative amounts, rate limit
    // ========================================================================
    console.log('--- [Category 5/5] Security, Auth, Quotas & Edge Boundaries (75 Cases) ---');

    // 15 Unauthenticated calls
    for (let i = 0; i < 15; i++) {
        await recordTest(`SEC-UNAUTH-${i + 1}`, `Reject unauthenticated call #${i + 1}`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: { 'x-forwarded-for': `198.51.100.${i + 50}` },
                body: { transactionId: 'tx-unauth', receiverUpi: 'user@okaxis' }
            }, res);
            assert.equal(res.statusCode, 401);
            assert.equal(res.body.error, 'UNAUTHORIZED');
        });
    }

    // 15 Insufficient Scope calls
    for (let i = 0; i < 15; i++) {
        await recordTest(`SEC-SCOPE-${i + 1}`, `Reject insufficient scope #${i + 1}`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: {
                    'x-api-key': keyNoScope,
                    'x-verifypulse-key-id': 'noscope-financial-corp',
                    'x-forwarded-for': `198.51.100.${i + 70}`
                },
                body: { transactionId: 'tx-scope', receiverUpi: 'user@okaxis' }
            }, res);
            assert.equal(res.statusCode, 403);
            assert.equal(res.body.error, 'INSUFFICIENT_SCOPE');
        });
    }

    // 15 Tier 1 Downgrade calls (Only Tier 2+ allowed)
    for (let i = 0; i < 15; i++) {
        await recordTest(`SEC-TIER-${i + 1}`, `Reject Tier 1 starter key #${i + 1}`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: {
                    'x-api-key': keyTier1,
                    'x-verifypulse-key-id': 'starter-financial-corp',
                    'x-forwarded-for': `198.51.100.${i + 90}`
                },
                body: { transactionId: 'tx-tier', receiverUpi: 'user@okaxis' }
            }, res);
            assert.equal(res.statusCode, 403);
            assert.equal(res.body.error, 'UPGRADE_REQUIRED');
        });
    }

    // 15 Missing Data / Null Body / Missing Identifiers
    for (let i = 0; i < 15; i++) {
        await recordTest(`SEC-MISSING-${i + 1}`, `Reject missing transactionId/identifiers #${i + 1}`, async () => {
            const res = mockRes();
            const bodyPayload = i % 3 === 0 ? null : (i % 3 === 1 ? { transactionId: 'tx-no-rec' } : { receiverUpi: 'user@okaxis' });
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 110),
                body: bodyPayload
            }, res);
            assert.equal(res.statusCode, 400);
            assert.equal(res.body.error, 'MISSING_DATA');
        });
    }

    // 10 Negative & Extreme Edge Amounts
    for (let i = 0; i < 10; i++) {
        await recordTest(`SEC-EDGE-AMT-${i + 1}`, `Safe handling of negative/extreme amount #${i + 1}`, async () => {
            const res = mockRes();
            await payguardHandler({
                method: 'POST',
                headers: getProHeaders(i + 130),
                body: {
                    transactionId: `tx-neg-${i}`,
                    amount: -5000,
                    receiverUpi: 'regular.borrower@okaxis'
                }
            }, res);
            assert.equal(res.statusCode, 200);
            assert.ok(res.body.flags.includes('INVALID_NEGATIVE_AMOUNT'), 'Should flag negative amount');
            assert.ok(res.body.riskScore >= 50);
        });
    }

    // 5 Rate Limit Burst Tests (Simulate exceeding 120 calls from 1 IP)
    for (let i = 0; i < 5; i++) {
        await recordTest(`SEC-RATELIMIT-${i + 1}`, `Rate limit burst handling #${i + 1}`, async () => {
            const burstIp = `198.51.100.222`; // Single fixed IP for burst
            let lastStatusCode = 200;
            for (let r = 0; r < 125; r++) {
                const res = mockRes();
                await payguardHandler({
                    method: 'POST',
                    headers: {
                        'x-api-key': keyTier2,
                        'x-verifypulse-key-id': 'pro-financial-corp',
                        'x-forwarded-for': burstIp
                    },
                    body: {
                        transactionId: `tx-burst-${r}`,
                        receiverUpi: 'burst.test@okaxis'
                    }
                }, res);
                lastStatusCode = res.statusCode;
            }
            assert.equal(lastStatusCode, 429, 'Excess calls should be RATE_LIMITED (429)');
        });
    }

    // ========================================================================
    // FINAL GAUNTLET SUMMARY AUDIT
    // ========================================================================
    console.log('\n========================================================================');
    console.log('   FEATURE #3 GAUNTLET SUMMARY AUDIT METRICS                            ');
    console.log('========================================================================');
    console.log(`Total Cases Tested:      ${passedCount + failedCount}`);
    console.log(`Total Passed:            ${passedCount} ✅`);
    console.log(`Total Failed:            ${failedCount} ❌`);
    console.log(`Success Rate:            ${((passedCount / (passedCount + failedCount)) * 100).toFixed(2)}%`);

    if (failures.length > 0) {
        console.log('\n--- DETECTED FAILURES ---');
        failures.forEach(f => console.log(`[${f.id}] ${f.name} => ${f.error}`));
        process.exit(1);
    }

    latencies.sort((a, b) => a - b);
    const min = latencies[0].toFixed(3);
    const avg = (latencies.reduce((sum, v) => sum + v, 0) / latencies.length).toFixed(3);
    const p95 = latencies[Math.floor(latencies.length * 0.95)].toFixed(3);
    const p99 = latencies[Math.floor(latencies.length * 0.99)].toFixed(3);
    const max = latencies[latencies.length - 1].toFixed(3);

    console.log('\n--- LATENCY & THROUGHPUT BENCHMARK ---');
    console.log(`Min Latency: ${min} ms`);
    console.log(`Avg Latency: ${avg} ms`);
    console.log(`P95 Latency: ${p95} ms`);
    console.log(`P99 Latency: ${p99} ms`);
    console.log(`Max Latency: ${max} ms`);
    console.log('\n🎉 100% PERFECT SCORE! All 450 enterprise tests passed with ZERO failures!');
    console.log('========================================================================\n');
}

executeGauntlet().catch(err => {
    console.error('Gauntlet runner fatal error:', err);
    process.exit(1);
});
