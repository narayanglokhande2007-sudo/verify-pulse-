const puppeteer = require('puppeteer-core');
const dns = require('dns').promises;

async function analyzeUrl(url) {
    let browser;
    try {
        browser = await puppeteer.launch({
            executablePath: '/usr/bin/chromium',
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
            headless: true
        });

        const page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 800 });
        await page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1');

        const response = await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
        
        const analysis = {
            status: response ? response.status() : 'OK',
            hasForms: false,
            hasPasswordFields: false,
            detectedBrand: null,
            isSuspicious: false,
            reason: [],
            screenshot: null,
            fingerprint: {}
        };

        // 1. Capture Screenshot (Visual Forensics)
        if (!url.startsWith('file://')) {
            const screenshotBuffer = await page.screenshot({ encoding: 'base64' });
            analysis.screenshot = screenshotBuffer;
        }

        // 2. Infrastructure Fingerprinting
        try {
            const domain = new URL(url).hostname;
            const addresses = await dns.resolve4(domain);
            analysis.fingerprint.ip = addresses[0];
            // In a real production environment, we would look up ASN/Hosting Provider here
        } catch (e) {
            analysis.fingerprint.error = "Could not resolve IP";
        }

        // 3. Behavioral Analysis
        const forms = await page.$$('form');
        if (forms.length > 0) {
            analysis.hasForms = true;
            const passwordFields = await page.$$('input[type="password"]');
            if (passwordFields.length > 0) {
                analysis.hasPasswordFields = true;
                analysis.isSuspicious = true;
                analysis.reason.push("Found password/OTP input field on an unverified domain.");
            }
        }

        const content = await page.content();
        const brands = ['SBI', 'HDFC', 'Paytm', 'PhonePe', 'KBC', 'Airtel', 'Jio'];
        for (const brand of brands) {
            if (content.includes(brand)) {
                analysis.detectedBrand = brand;
                if (!url.toLowerCase().includes(brand.toLowerCase())) {
                    analysis.isSuspicious = true;
                    analysis.reason.push(`Visual/Text match for '${brand}' detected on suspicious URL.`);
                }
            }
        }

        return analysis;

    } catch (error) {
        return { error: error.message, isSuspicious: false, reason: ["Error during analysis: " + error.message] };
    } finally {
        if (browser) await browser.close();
    }
}

module.exports = { analyzeUrl };
