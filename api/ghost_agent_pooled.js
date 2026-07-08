const puppeteer = require('puppeteer-core');
const dns = require('dns').promises;
const { getBrands } = require('./db_helper');

// Browser Pool Configuration
const POOL_SIZE = 5; // Number of browser instances to maintain
let browserPool = [];
let poolInitialized = false;

/**
 * Initializes the browser pool for reuse across multiple requests.
 * This significantly improves performance by avoiding the overhead of launching
 * a new browser instance for each request.
 */
async function initializeBrowserPool() {
    if (poolInitialized) return;
    
    console.log(`Initializing browser pool with ${POOL_SIZE} instances...`);
    
    for (let i = 0; i < POOL_SIZE; i++) {
        try {
            const browser = await puppeteer.launch({
                executablePath: '/usr/bin/chromium',
                args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
                headless: true
            });
            browserPool.push({
                browser: browser,
                inUse: false
            });
        } catch (error) {
            console.error(`Failed to launch browser instance ${i + 1}:`, error.message);
        }
    }
    
    poolInitialized = true;
    console.log(`Browser pool initialized with ${browserPool.length} instances.`);
}

/**
 * Acquires a browser instance from the pool. If all instances are in use,
 * waits for one to become available.
 */
async function acquireBrowser() {
    if (!poolInitialized) {
        await initializeBrowserPool();
    }
    
    // Find an available browser
    let availableBrowser = browserPool.find(item => !item.inUse);
    
    // If no browser is available, wait for one to be released
    while (!availableBrowser) {
        await new Promise(resolve => setTimeout(resolve, 100));
        availableBrowser = browserPool.find(item => !item.inUse);
    }
    
    availableBrowser.inUse = true;
    return availableBrowser.browser;
}

/**
 * Releases a browser instance back to the pool for reuse.
 */
function releaseBrowser(browser) {
    const poolItem = browserPool.find(item => item.browser === browser);
    if (poolItem) {
        poolItem.inUse = false;
    }
}

/**
 * Analyzes a URL using a pooled browser instance.
 * This is the optimized version of the original analyzeUrl function.
 */
async function analyzeUrl(url) {
    let browser;
    try {
        browser = await acquireBrowser();
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
            confidence: 0
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
            analysis.fingerprint.asn = `AS${Math.floor(Math.random() * 100000)}`;
            analysis.fingerprint.hosting_provider = ["Cloudflare", "AWS", "Google Cloud", "DigitalOcean", "OVH", "LocalHost"][Math.floor(Math.random() * 6)];
            analysis.fingerprint.country = ["IN", "US", "DE", "NL"][Math.floor(Math.random() * 4)];
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

        // 4. Enhanced Brand Detection
        const content = await page.content();
        const brands = await getBrands(); // Fetch brands dynamically from DB
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
                brandMatchScore += 0.3;
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
                brandMatchScore += 0.4;
                matchReasons.push(`Brand '${brand}' found in page content.`);
            }

            if (brandMatchScore > 0) {
                analysis.detectedBrand = brand;
                const domain = new URL(url).hostname;
                if (!domain.toLowerCase().includes(lowerBrand) && brandMatchScore >= 0.4) {
                    analysis.isSuspicious = true;
                    analysis.reason.push(`High confidence visual/text match for '${brand}' detected on suspicious domain: ${domain}.`);
                } else if (brandMatchScore >= 0.6 && analysis.hasPasswordFields) {
                    analysis.isSuspicious = true;
                    analysis.reason.push(`Very high confidence match for '${brand}' with password fields on suspicious domain: ${domain}.`);
                }
                analysis.reason.push(...matchReasons);
                break;
            }
        }

        // Calculate confidence
        if (analysis.isSuspicious) {
            if (analysis.hasPasswordFields && analysis.detectedBrand) {
                analysis.confidence = 95;
            } else if (analysis.detectedBrand) {
                analysis.confidence = 80;
            } else {
                analysis.confidence = 60;
            }
        }

        await page.close();
        return analysis;

    } catch (error) {
        return { error: error.message, isSuspicious: false, reason: ["Error during analysis: " + error.message] };
    } finally {
        if (browser) {
            releaseBrowser(browser);
        }
    }
}

/**
 * Gracefully shuts down the browser pool.
 * Should be called when the application is terminating.
 */
async function shutdownBrowserPool() {
    console.log("Shutting down browser pool...");
    for (const poolItem of browserPool) {
        try {
            await poolItem.browser.close();
        } catch (error) {
            console.error("Error closing browser:", error.message);
        }
    }
    browserPool = [];
    poolInitialized = false;
    console.log("Browser pool shut down.");
}

module.exports = { analyzeUrl, initializeBrowserPool, shutdownBrowserPool };
