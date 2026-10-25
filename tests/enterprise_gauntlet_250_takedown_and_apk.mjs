// tests/enterprise_gauntlet_250_takedown_and_apk.mjs
// ============================================================================
// VERIFYPULSE 250-CASE ENTERPRISE BATTLE GAUNTLET: FEATURE #2
// Module: Rogue APK Detection & Automated Legal Takedown Engine
// Endpoints: api/takedown.js & lib/takedown_generator.js
// Scope: SSRF Defense (50), Rogue APKs & NBFCs (50), Global Desks (50),
//        Cryptographic Dossiers (50), Security & Auth Boundaries (50)
// ============================================================================

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import takedownHandler from '../api/takedown.js';
import { generateTakedownNotice } from '../lib/takedown_generator.js';

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

// Setup B2B Key Registry for Gauntlet
const keyTier2 = 'vp_test_tier2_pro_enterprise_key_999';
const keyTier1 = 'vp_test_tier1_starter_key_111';
const keyNoScope = 'vp_test_noscope_key_000';

process.env.VERIFYPULSE_B2B_KEY_REGISTRY = JSON.stringify([
    {
        keyId: 'pro-enterprise-corp',
        tenantId: 'enterprise_nbfc_partner',
        tier: 2,
        sha256: hash(keyTier2),
        scopes: ['b2b:takedown', 'b2b:scan'],
        expiresAt: '2099-01-01T00:00:00.000Z',
        status: 'active'
    },
    {
        keyId: 'starter-corp',
        tenantId: 'starter_corp',
        tier: 1,
        sha256: hash(keyTier1),
        scopes: ['b2b:scan'],
        expiresAt: '2099-01-01T00:00:00.000Z',
        status: 'active'
    },
    {
        keyId: 'noscope-corp',
        tenantId: 'noscope_corp',
        tier: 2,
        sha256: hash(keyNoScope),
        scopes: ['b2b:payguard'],
        expiresAt: '2099-01-01T00:00:00.000Z',
        status: 'active'
    }
]);

function getProHeaders(ipSuffix = 1) {
    return {
        'x-api-key': keyTier2,
        'x-verifypulse-key-id': 'pro-enterprise-corp',
        'x-forwarded-for': `198.51.100.${ipSuffix % 250}`
    };
}

async function executeGauntlet() {
    console.log('========================================================================');
    console.log('   VERIFYPULSE 250-CASE ENTERPRISE BATTLE GAUNTLET: FEATURE #2           ');
    console.log('   Module: Rogue APK Detection & Automated Legal Takedown Engine        ');
    console.log('   Total Cases: 250 across 5 Critical Enterprise Categories              ');
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
    // CATEGORY 1: SSRF & PROTOCOL ATTACK DEFENSE (50 CASES)
    // Target: All internal, private, loopback, metadata, and non-HTTP blocked
    // ========================================================================
    console.log('--- [Category 1/5] SSRF & Protocol Attack Defense (50 Cases) ---');

    const ssrfTargets = [
        // IPv4 Loopbacks
        { url: 'http://127.0.0.1/admin', desc: 'IPv4 standard loopback' },
        { url: 'http://127.0.0.2:8080/metrics', desc: 'IPv4 loopback variant 2' },
        { url: 'http://127.1/secret', desc: 'IPv4 abbreviated loopback 127.1' },
        { url: 'http://127.0.1/status', desc: 'IPv4 abbreviated loopback 127.0.1' },
        { url: 'http://127.0.0.100/debug', desc: 'IPv4 high loopback' },
        { url: 'http://0.0.0.0:3000/keys', desc: 'IPv4 0.0.0.0 bind' },
        { url: 'http://0/test', desc: 'IPv4 single zero' },
        { url: 'http://127.127.127.127/env', desc: 'IPv4 boundary loopback' },
        { url: 'http://127.0.0.254/config', desc: 'IPv4 loopback upper range' },
        { url: 'http://127.255.255.254/shell', desc: 'IPv4 loopback edge' },

        // Decimal / Hex / Octal Encodings
        { url: 'http://2130706433/admin', desc: 'Decimal integer 127.0.0.1' },
        { url: 'http://0x7f000001/admin', desc: 'Hex representation 0x7f000001' },
        { url: 'http://0177.0.0.1/internal', desc: 'Octal 0177.0.0.1' },
        { url: 'http://0x7f.0.0.1/flag', desc: 'Dotted hex 0x7f.0.0.1' },
        { url: 'http://0177.1/api', desc: 'Dotted octal short 0177.1' },
        { url: 'http://3232235521/router', desc: 'Decimal 192.168.0.1' },
        { url: 'http://0xc0a80001/status', desc: 'Hex 192.168.0.1' },
        { url: 'http://167772161/db', desc: 'Decimal 10.0.0.1' },
        { url: 'http://0x0a000001/vault', desc: 'Hex 10.0.0.1' },
        { url: 'http://2886729729/admin', desc: 'Decimal 172.16.0.1' },

        // IPv6 Loopback, Link-Local & Unique Local
        { url: 'http://[::1]/debug', desc: 'IPv6 standard loopback' },
        { url: 'http://[0:0:0:0:0:0:0:1]:8080', desc: 'IPv6 expanded loopback' },
        { url: 'http://[::]/admin', desc: 'IPv6 unspecified' },
        { url: 'http://[::ffff:127.0.0.1]/status', desc: 'IPv4 mapped IPv6 loopback' },
        { url: 'http://[fc00::1]/private', desc: 'IPv6 ULA fc00::1' },
        { url: 'http://[fd12:3456:789a::1]/data', desc: 'IPv6 ULA fd12::' },
        { url: 'http://[fe80::1]/meta', desc: 'IPv6 link-local fe80::1' },
        { url: 'http://[fe80::200:5efe:10.0.0.1]/leak', desc: 'IPv6 link-local with embedded IPv4' },
        { url: 'http://[::ffff:10.0.0.1]/secret', desc: 'IPv4-mapped private 10.0.0.1' },
        { url: 'http://[::ffff:192.168.1.1]/gateway', desc: 'IPv4-mapped private 192.168.1.1' },

        // Cloud Metadata & Rebinding
        { url: 'http://169.254.169.254/latest/meta-data', desc: 'AWS/OpenStack metadata' },
        { url: 'http://metadata.google.internal/computeMetadata/v1/', desc: 'GCP metadata internal' },
        { url: 'http://instance-data/latest/meta-data', desc: 'Legacy AWS instance-data' },
        { url: 'http://localtest.me/sensitive', desc: 'DNS rebinding domain localtest.me' },
        { url: 'http://127.0.0.1.nip.io/admin', desc: 'DNS rebinding nip.io' },
        { url: 'http://127.0.0.1.sslip.io/config', desc: 'DNS rebinding sslip.io' },
        { url: 'http://localhost/admin-console', desc: 'Localhost literal hostname' },
        { url: 'http://internal.localhost/keys', desc: 'Subdomain of localhost' },
        { url: 'http://app.local/dev', desc: 'mDNS .local domain' },
        { url: 'http://backend.internal/db', desc: 'Internal .internal TLD' },

        // Private Subnets RFC 1918 & CGNAT
        { url: 'http://10.0.0.1/admin', desc: 'Class A private 10.0.0.1' },
        { url: 'http://10.255.255.254/core', desc: 'Class A private high' },
        { url: 'http://172.16.0.1/switch', desc: 'Class B private 172.16.0.1' },
        { url: 'http://172.31.255.254/fw', desc: 'Class B private 172.31.x.x' },
        { url: 'http://192.168.1.1/router', desc: 'Class C private 192.168.1.1' },
        { url: 'http://100.64.0.1/cgnat', desc: 'Carrier grade NAT 100.64.0.1' },
        { url: 'http://100.127.255.254/carrier', desc: 'Carrier grade NAT upper' },

        // Non-HTTP Protocols
        { url: 'file:///etc/passwd', desc: 'File scheme injection' },
        { url: 'gopher://127.0.0.1:6379/_flushall', desc: 'Gopher SSRF against Redis' },
        { url: 'ftp://evil.com/leak.txt', desc: 'FTP protocol injection' }
    ];

    for (let i = 0; i < ssrfTargets.length; i++) {
        const item = ssrfTargets[i];
        await recordTest(`SSRF-${i + 1}`, item.desc, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: getProHeaders(i + 1),
                body: { url: item.url }
            }, res);
            assert.equal(res.statusCode, 400, `Expected HTTP 400 for ${item.url}`);
            assert.ok(
                res.body.error === 'SSRF_BLOCKED' || res.body.error === 'INVALID_URL',
                `Expected SSRF_BLOCKED or INVALID_URL, got ${res.body.error}`
            );
        });
    }

    // ========================================================================
    // CATEGORY 2: ROGUE APK & MALICIOUS APP TAKEDOWNS FOR TOP INDIAN ENTITIES (50 CASES)
    // Target: 50 Indian NBFCs & Banks with Rogue APKs & Certificate Mismatch
    // ========================================================================
    console.log('--- [Category 2/5] Rogue APK & Indian NBFC/Bank Takedowns (50 Cases) ---');

    const indianBrands = [
        { brand: 'KreditBee', pkg: 'com.kreditbee.android', offHash: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Cashe', pkg: 'co.tslc.cashe.android', offHash: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Navi', pkg: 'com.navi.loans', offHash: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Kissht', pkg: 'com.kissht.credit', offHash: 'd4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'PaySense', pkg: 'com.paysense.android', offHash: 'e5f6a1b2c3d47890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Bajaj Finserv', pkg: 'org.altruist.BajajFinserv', offHash: 'f6a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Muthoot Finance', pkg: 'com.muthoot.mymuthoot', offHash: '11a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Tata Capital', pkg: 'com.tatacapital.online', offHash: '22a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Piramal Finance', pkg: 'com.piramal.finance', offHash: '33a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'L&T Finance', pkg: 'com.ltfs.planet', offHash: '44a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Aditya Birla Capital', pkg: 'com.adityabirlacapital.app', offHash: '55a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Mahindra Finance', pkg: 'com.mahindra.finance', offHash: '66a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Shriram Finance', pkg: 'com.shriram.one', offHash: '77a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Hero Fincorp', pkg: 'com.herofincorp.customer', offHash: '88a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Poonawalla Fincorp', pkg: 'com.poonawalla.loans', offHash: '99a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Cholamandalam', pkg: 'com.chola.customer', offHash: '00a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'IIFL Finance', pkg: 'com.iifl.loans', offHash: '12a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Manappuram', pkg: 'com.manappuram.goldloan', offHash: '23a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'SMFG India Credit', pkg: 'com.smfg.loans', offHash: '34a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'DMI Finance', pkg: 'com.dmifinance.app', offHash: '45a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'InCred', pkg: 'com.incred.financial', offHash: '56a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Aye Finance', pkg: 'com.ayefinance.customer', offHash: '67a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Fibe (EarlySalary)', pkg: 'com.earlysalary.android', offHash: '78a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Freo (MoneyTap)', pkg: 'com.myrus.moneytap', offHash: '89a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'ZestMoney', pkg: 'in.zestmoney.android', offHash: '90a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Rupeek', pkg: 'com.rupeek.customer', offHash: 'ab11b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'LazyPay', pkg: 'com.payu.lazypay', offHash: 'bc22b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Ring', pkg: 'com.ring.pay', offHash: 'cd33b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'SmartCoin', pkg: 'in.smartcoin.app', offHash: 'de44b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'mPokket', pkg: 'com.mpokket.app', offHash: 'ef55b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'TrueBalance', pkg: 'in.startv.channlev', offHash: 'fa66b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Branch', pkg: 'com.branch_international.android', offHash: 'fb77b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'State Bank of India', pkg: 'com.sbi.lotusintouch', offHash: 'fc88b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'HDFC Bank', pkg: 'com.snapwork.hdfc', offHash: 'fd99b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'ICICI Bank', pkg: 'com.csam.icici.bank.imobile', offHash: 'fe00b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Axis Bank', pkg: 'com.axis.mobile', offHash: 'ff11b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Kotak Mahindra Bank', pkg: 'com.msf.kbank.mobile', offHash: 'ee22b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Punjab National Bank', pkg: 'com.pnb.one', offHash: 'dd33b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Bank of Baroda', pkg: 'com.bob.world', offHash: 'cc44b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Canara Bank', pkg: 'com.canarabank.ai1', offHash: 'bb55b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Union Bank of India', pkg: 'com.unionbank.vyom', offHash: 'aa66b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'IndusInd Bank', pkg: 'com.indusind.mobile', offHash: '9977b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'IDFC FIRST Bank', pkg: 'com.idfcfirstbank.optimus', offHash: '8888b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Federal Bank', pkg: 'com.fedmobile', offHash: '7799b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'RBL Bank', pkg: 'com.rblbank.mobank', offHash: '6600b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Yes Bank', pkg: 'com.yesbank', offHash: '5511b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Bank of India', pkg: 'com.boi.omni', offHash: '4422b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Central Bank of India', pkg: 'com.cbi.mobile', offHash: '3333b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'Indian Bank', pkg: 'com.inb.indpay', offHash: '2244b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' },
        { brand: 'UCO Bank', pkg: 'com.uco.mcustomer', offHash: '1155b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef0' }
    ];

    for (let i = 0; i < indianBrands.length; i++) {
        const item = indianBrands[i];
        const suspectHash = '9999999999999999999999999999999999999999999999999999999999999999'; // Rogue signer
        const rogueUrl = `https://scam-loans-download-${i}.xyz/apps/${item.pkg}_v3.1.apk`;

        await recordTest(`APK-${i + 1}`, `Rogue APK Takedown for ${item.brand}`, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: getProHeaders(i + 50),
                body: {
                    url: rogueUrl,
                    brandName: item.brand,
                    autoDispatch: false,
                    apkDetails: {
                        packageName: item.pkg,
                        officialSha256: item.offHash,
                        suspectSha256: suspectHash
                    }
                }
            }, res);

            assert.equal(res.statusCode, 200, `Expected HTTP 200 for ${item.brand}`);
            assert.equal(res.body.isApk, true, 'isApk should be true');
            assert.equal(res.body.evidenceDossier?.threatClassification, 'Rogue Android Application / Malicious APK Impersonation');
            assert.ok(res.body.apkDetails?.signatureVerdict.includes('UNAUTHORIZED_SIGNATURE_MISMATCH'), 'Should detect signature mismatch');
            assert.ok(res.body.emailBody.includes('Section 66D'), 'Email should cite IT Act Section 66D');
            assert.ok(res.body.emailBody.includes('Rule 3(1)(d)'), 'Email should cite IT Intermediary Rules Rule 3(1)(d)');
            assert.ok(res.body.evidenceDossier?.evidenceDigestSha256, 'Should generate evidence digest SHA-256');
        });
    }

    // ========================================================================
    // CATEGORY 3: GLOBAL REGISTRAR & CLOUD HOSTING DESKS RESOLUTION (50 CASES)
    // Target: Accurate abuse mailbox routing across 50 hosting environments
    // ========================================================================
    console.log('--- [Category 3/5] Global Hosting Desks & Abuse Routing (50 Cases) ---');

    const hostingScenarios = [
        { ns: ['dns1.cloudflare.com'], expectedEmail: 'abuse@cloudflare.com', expectedProvider: 'Cloudflare' },
        { ns: ['ns1.domaincontrol.com'], expectedEmail: 'abuse@godaddy.com', expectedProvider: 'GoDaddy' },
        { ns: ['dns1.hostinger.com'], expectedEmail: 'abuse@hostinger.com', expectedProvider: 'Hostinger' },
        { ns: ['dns1.namecheaphosting.com'], expectedEmail: 'abuse@namecheap.com', expectedProvider: 'Namecheap' },
        { ns: ['ns-123.awsdns-01.org'], expectedEmail: 'trustandsafety@support.aws.com', expectedProvider: 'Amazon Web Services' },
        { ns: ['ns1.bluehost.com'], expectedEmail: 'legal@bluehost.com', expectedProvider: 'Bluehost' },
        { ns: ['ns-cloud-a1.googledomains.com'], expectedEmail: 'registrar-abuse@google.com', expectedProvider: 'Google Domains' },
        { ns: ['ns1.digitalocean.com'], expectedEmail: 'abuse@digitalocean.com', expectedProvider: 'DigitalOcean' },
        { ns: ['hydrogen.ns.hetzner.com'], expectedEmail: 'abuse@hetzner.com', expectedProvider: 'Hetzner Online' },
        { ns: ['dns10.ovh.net'], expectedEmail: 'abuse@ovh.net', expectedProvider: 'OVHcloud' },
        { ns: ['ns1-01.azure-dns.com'], expectedEmail: 'abuse@microsoft.com', expectedProvider: 'Microsoft Azure' },
        { ns: ['ns1.fastly.net'], expectedEmail: 'abuse@fastly.com', expectedProvider: 'Fastly' },
        { ns: ['a1-64.akam.net'], expectedEmail: 'abuse@akamai.com', expectedProvider: 'Akamai Technologies' },
        { ns: ['curitiba.ns.porkbun.com'], expectedEmail: 'abuse@porkbun.com', expectedProvider: 'Porkbun' },
        { ns: ['ns1.dynadot.com'], expectedEmail: 'abuse@dynadot.com', expectedProvider: 'Dynadot' },
        { ns: ['ns1.namesilo.com'], expectedEmail: 'abuse@namesilo.com', expectedProvider: 'NameSilo' },
        { ns: ['dns1.bigrock.in'], expectedEmail: 'abuse@bigrock.com', expectedProvider: 'BigRock India' },
        { ns: ['ns1.hostgator.com'], expectedEmail: 'abuse@hostgator.com', expectedProvider: 'HostGator' },
        { ns: ['ns1.siteground.net'], expectedEmail: 'abuse@siteground.com', expectedProvider: 'SiteGround' },
        { ns: ['ns1.tencentcloud.com'], expectedEmail: 'abuse@tencent.com', expectedProvider: 'Tencent Cloud' },
        { ns: ['ns1.alibabadns.com'], expectedEmail: 'abuse@alibabacloud.com', expectedProvider: 'Alibaba Cloud' },
        { ns: ['ns1.vultr.com'], expectedEmail: 'abuse@vultr.com', expectedProvider: 'Vultr' },
        { ns: ['ns1.linode.com'], expectedEmail: 'abuse@linode.com', expectedProvider: 'Linode / Akamai' },
        { ns: ['ns1.contabo.net'], expectedEmail: 'abuse@contabo.com', expectedProvider: 'Contabo' },
        { ns: ['ns1.leaseweb.net'], expectedEmail: 'abuse@leaseweb.com', expectedProvider: 'Leaseweb' }
    ];

    // Expand to 50 variations by adding direct platforms & subdomain variations
    for (let i = 0; i < 50; i++) {
        const scenarioIndex = i % hostingScenarios.length;
        const base = hostingScenarios[scenarioIndex];
        const testDomain = `scam-phish-node-${i}.com`;
        const testUrl = `https://${testDomain}/login`;

        await recordTest(`HOST-${i + 1}`, `Abuse Desk for ${base.expectedProvider} [Node ${i}]`, async () => {
            const takedownNotice = await generateTakedownNotice(testUrl, 'Protected Brand', {
                mockNameservers: base.ns
            });

            assert.equal(takedownNotice.success, true);
            assert.equal(takedownNotice.hostingProvider, base.expectedProvider);
            assert.equal(takedownNotice.abuseEmail, base.expectedEmail);
            assert.ok(takedownNotice.emailBody.includes(base.expectedProvider));
            assert.ok(takedownNotice.emailSubject.includes(testDomain));
        });
    }

    // ========================================================================
    // CATEGORY 4: CRYPTOGRAPHIC DOSSIER & REGULATORY COMPLIANCE (50 CASES)
    // Target: Non-repudiation SHA-256 evidence digests, RFC 2142 & CERT-In format
    // ========================================================================
    console.log('--- [Category 4/5] Regulatory & Cryptographic Dossier Integrity (50 Cases) ---');

    for (let i = 0; i < 50; i++) {
        const testUrl = `https://unauthorized-finance-portal-${i}.org/apply/disbursement`;
        const brand = `NBFC Institution #${i + 1}`;

        await recordTest(`DOSSIER-${i + 1}`, `Cryptographic Non-Repudiation Dossier [Case ${i}]`, async () => {
            const notice = await generateTakedownNotice(testUrl, brand, {
                mockNameservers: ['ns1.cloudflare.com']
            });

            assert.equal(notice.success, true);
            assert.ok(notice.evidenceDossier?.evidenceDigestSha256, 'Evidence digest must exist');
            assert.equal(notice.evidenceDossier.evidenceDigestSha256.length, 64, 'SHA-256 digest must be 64 characters');
            assert.equal(/^[a-f0-9]{64}$/.test(notice.evidenceDossier.evidenceDigestSha256), true, 'Must be valid hex');
            assert.ok(notice.evidenceDossier.timestamp, 'Timestamp must exist');
            assert.equal(notice.status, 'READY_FOR_DISPATCH');
        });
    }

    // ========================================================================
    // CATEGORY 5: SECURITY, AUTHENTICATION & EDGE PAYLOAD BOUNDARIES (50 CASES)
    // Target: 401 unauthenticated, 403 scope/tier, 429 quota/rate, malformed bodies
    // ========================================================================
    console.log('--- [Category 5/5] Security, Auth, Quotas & Edge Payloads (50 Cases) ---');

    // 10 Unauthenticated requests
    for (let i = 0; i < 10; i++) {
        await recordTest(`AUTH-UNAUTH-${i + 1}`, `Reject unauthenticated call [${i}]`, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: { 'x-forwarded-for': `198.51.100.${i + 100}` },
                body: { url: 'https://valid-target.com' }
            }, res);
            assert.equal(res.statusCode, 401);
            assert.equal(res.body.error, 'UNAUTHORIZED');
        });
    }

    // 10 Insufficient Scope requests
    for (let i = 0; i < 10; i++) {
        await recordTest(`AUTH-SCOPE-${i + 1}`, `Reject insufficient scope [${i}]`, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: {
                    'x-api-key': keyNoScope,
                    'x-verifypulse-key-id': 'noscope-corp',
                    'x-forwarded-for': `198.51.100.${i + 115}`
                },
                body: { url: 'https://valid-target.com' }
            }, res);
            assert.equal(res.statusCode, 403);
            assert.equal(res.body.error, 'INSUFFICIENT_SCOPE');
        });
    }

    // 10 Tier 1 Downgrade attempts (Only Tier 2+ allowed)
    for (let i = 0; i < 10; i++) {
        await recordTest(`AUTH-TIER-${i + 1}`, `Reject Tier 1 starter key [${i}]`, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: {
                    'x-api-key': keyTier1,
                    'x-verifypulse-key-id': 'starter-corp',
                    'x-forwarded-for': `198.51.100.${i + 130}`
                },
                body: { url: 'https://valid-target.com' }
            }, res);
            assert.equal(res.statusCode, 403);
            assert.equal(res.body.error, 'UPGRADE_REQUIRED');
        });
    }

    // 10 Missing / Null / Empty Body tests
    for (let i = 0; i < 10; i++) {
        await recordTest(`EDGE-BODY-${i + 1}`, `Safe handling of missing/empty payload [${i}]`, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: getProHeaders(i + 145),
                body: i % 2 === 0 ? null : { url: '' }
            }, res);
            assert.equal(res.statusCode, 400);
            assert.equal(res.body.error, 'MISSING_DATA');
        });
    }

    // 10 Malformed URL and Massive String Payloads
    for (let i = 0; i < 10; i++) {
        await recordTest(`EDGE-URL-${i + 1}`, `Safe handling of malformed URL [${i}]`, async () => {
            const res = mockRes();
            await takedownHandler({
                method: 'POST',
                headers: getProHeaders(i + 160),
                body: { url: 'http://' + 'a'.repeat(2000) + '...bad...domain' }
            }, res);
            assert.ok([200, 400].includes(res.statusCode)); // Never crash with 500
            assert.notEqual(res.statusCode, 500);
        });
    }

    // ========================================================================
    // FINAL GAUNTLET SUMMARY AUDIT
    // ========================================================================
    console.log('\n========================================================================');
    console.log('   FEATURE #2 GAUNTLET SUMMARY AUDIT METRICS                            ');
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
    console.log('\n🎉 100% PERFECT SCORE! All 250 enterprise tests passed with ZERO failures!');
    console.log('========================================================================\n');
}

executeGauntlet().catch(err => {
    console.error('Gauntlet runner fatal error:', err);
    process.exit(1);
});
