const puppeteer = require('puppeteer-core');

async function analyzeUrl(url) {
    let browser;
    try {
        // Launching in stealth/headless mode
        browser = await puppeteer.launch({
            executablePath: '/usr/bin/chromium-browser',
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
            headless: true
        });

        const page = await browser.newPage();
        
        // Setting a real user agent to avoid detection
        await page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1');

        console.log(`[GhostAgent] Navigating to: ${url}`);
        
        const response = await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 });
        
        const analysis = {
            status: response.status(),
            hasForms: false,
            hasPasswordFields: false,
            hasAutoDownload: false,
            detectedBrand: null,
            isSuspicious: false,
            reason: []
        };

        // 1. Check for Phishing Forms
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

        // 2. Check for Visual Brand Imitation (Keywords)
        const content = await page.content();
        const brands = ['SBI', 'HDFC', 'Paytm', 'PhonePe', 'KBC', 'Airtel', 'Jio'];
        for (const brand of brands) {
            if (content.includes(brand)) {
                analysis.detectedBrand = brand;
                if (!url.includes(brand.toLowerCase())) {
                    analysis.isSuspicious = true;
                    analysis.reason.push(`Page mentions '${brand}' but URL doesn't look official.`);
                }
            }
        }

        // 3. Check for Malicious Scripts/Redirects
        const finalUrl = page.url();
        if (finalUrl !== url) {
            analysis.reason.push(`URL redirected to: ${finalUrl}`);
            if (finalUrl.includes('.apk') || finalUrl.includes('.exe')) {
                analysis.hasAutoDownload = true;
                analysis.isSuspicious = true;
                analysis.reason.push("Detected potential malicious file download.");
            }
        }

        return analysis;

    } catch (error) {
        return { error: error.message, isSuspicious: false };
    } finally {
        if (browser) await browser.close();
    }
}

module.exports = { analyzeUrl };
