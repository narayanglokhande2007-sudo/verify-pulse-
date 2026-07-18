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
            fingerprint: {},
            confidence: 0 // New field for Ghost Agent's confidence
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
            // Simulate ASN and Hosting Provider lookup for demonstration
            analysis.fingerprint.asn = `AS${Math.floor(Math.random() * 100000)}`; // Simulated ASN
            analysis.fingerprint.hosting_provider = ["Cloudflare", "AWS", "Google Cloud", "DigitalOcean", "OVH", "LocalHost"][Math.floor(Math.random() * 6)]; // Simulated Hosting
            analysis.fingerprint.country = ["IN", "US", "DE", "NL"][Math.floor(Math.random() * 4)]; // Simulated Country

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
        const brands = ['SBI', 'HDFC', 'ICICI', 'Axis', 'Paytm', 'PhonePe', 'KBC', 'Airtel', 'Jio', 'Google', 'Microsoft', 'Apple'];
        const pageTitle = await page.title();
        const metaDescription = await page.$eval('head > meta[name="description"]', element => element.content).catch(() => '');

        for (const brand of brands) {
            const lowerBrand = brand.toLowerCase();
            const lowerUrl = url.toLowerCase();
            const lowerContent = content.toLowerCase();
            const lowerTitle = pageTitle.toLowerCase();
            const lowerMetaDescription = metaDescription.toLowerCase();

            let brandMatchScore = 0;
            let matchReasons = [];

            if (lowerUrl.includes(lowerBrand)) {
                brandMatchScore += 0.3; // Brand in URL is a strong indicator
                matchReasons.push(`Brand '${brand}' found in URL.`);
            }
            if (lowerTitle.includes(lowerBrand)) {
                brandMatchScore += 0.2;
                matchReasons.push(`Brand '${brand}' found in page title.`);
            }
            if (lowerMetaDescription.includes(lowerBrand)) {
                brandMatchScore += 0.1;
                matchReasons.push(`Brand '${brand}' found in meta description.`);
            }
            if (lowerContent.includes(lowerBrand)) {
                brandMatchScore += 0.4; // Brand in content is also strong
                matchReasons.push(`Brand '${brand}' found in page content.`);
            }

            if (brandMatchScore > 0) {
                analysis.detectedBrand = brand;
                // If brand is detected but not in the main domain of the URL, it's suspicious
                const domain = new URL(url).hostname;
                if (!domain.toLowerCase().includes(lowerBrand) && brandMatchScore >= 0.4) { // High confidence match outside domain
                    analysis.isSuspicious = true;
                    analysis.reason.push(`High confidence visual/text match for '${brand}' detected on suspicious domain: ${domain}.`);
                } else if (brandMatchScore >= 0.6 && analysis.hasPasswordFields) { // Very high confidence if also has password fields
                    analysis.isSuspicious = true;
                    analysis.reason.push(`Very high confidence match for '${brand}' with password fields on suspicious domain: ${domain}.`);
                }
                // Add all match reasons for transparency
                analysis.reason.push(...matchReasons);
                break; // Found a strong brand match, no need to check other brands
            }
        }

        // Calculate Ghost Agent's confidence
        if (analysis.isSuspicious) {
            if (analysis.hasPasswordFields && analysis.detectedBrand) {
                analysis.confidence = 95; // Very high confidence for phishing
            } else if (analysis.detectedBrand) {
                analysis.confidence = 80; // High confidence for brand impersonation
            } else {
                analysis.confidence = 60; // Moderate confidence for general suspicious behavior
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
