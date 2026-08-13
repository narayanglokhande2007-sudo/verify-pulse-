import puppeteer from 'puppeteer-core';
import { promises as dns } from 'dns';
import { isIP } from 'net';
import { getBrands } from './db_helper.js';

// Browser Pool Configuration
const POOL_SIZE = 5; // Number of browser instances to maintain
let browserPool = [];
let poolInitialized = false;

function isPrivateIpv4(address) {
    const [a, b] = address.split('.').map(Number);
    return a === 0
        || a === 10
        || a === 127
        || (a === 169 && b === 254)
        || (a === 172 && b >= 16 && b <= 31)
        || (a === 192 && b === 168)
        || a >= 224;
}

/**
 * Prevents the browser agent from being used as a proxy to internal services.
 * The agent only visits public HTTP(S) targets and does not accept credentials
 * embedded in URLs.
 */
async function validatePublicTarget(input) {
    const target = new URL(input);
    const hostname = target.hostname.toLowerCase();

    if (!['http:', 'https:'].includes(target.protocol)) {
        throw new Error('Only public HTTP(S) URLs are supported.');
    }
    if (target.username || target.password) {
        throw new Error('URLs with embedded credentials are not supported.');
    }
    if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
        throw new Error('Local or internal hosts are not supported.');
    }

    const addresses = isIP(hostname)
        ? [hostname]
        : await dns.resolve4(hostname);

    if (!addresses.length || addresses.some((address) => isPrivateIpv4(address))) {
        throw new Error('The target must resolve only to public IPv4 addresses.');
    }

    return { target, addresses };
}

/**
 * Initializes the browser pool for reuse across multiple requests.
 * This significantly improves performance by avoiding the overhead of launching
 * a new browser instance for each request.
 */
export async function initializeBrowserPool() {
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
export async function analyzeUrl(url) {
    let browser;
    try {
        const validatedTarget = await validatePublicTarget(url);
        browser = await acquireBrowser();
        const page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 800 });
        await page.setUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1');

        const attachmentResponses = [];
        page.on('response', async (resource) => {
            const disposition = resource.headers()['content-disposition'] || '';
            if (/attachment/i.test(disposition)) {
                attachmentResponses.push({ url: resource.url(), contentDisposition: disposition });
            }
        });

        const response = await page.goto(validatedTarget.target.toString(), { waitUntil: 'networkidle2', timeout: 20000 });
        // Observation window only: no clicking, typing, submitting, or OTP handling.
        await new Promise((resolve) => setTimeout(resolve, 750));
        
        const analysis = {
            status: response ? response.status() : 'OK',
            hasForms: false,
            hasPasswordFields: false,
            detectedBrand: null,
            isSuspicious: false,
            reason: [],
            screenshot: null,
            fingerprint: { ip: validatedTarget.addresses[0] },
            navigation: {
                requestedUrl: validatedTarget.target.toString(),
                finalUrl: response?.url?.() || validatedTarget.target.toString(),
                redirected: Boolean(response?.url?.() && response.url() !== validatedTarget.target.toString())
            },
            behavioralSignals: {
                interactiveElementCount: 0,
                passwordFieldCount: 0,
                otpFieldCount: 0,
                hiddenInputCount: 0,
                downloadLinkCount: 0,
                attachmentResponseCount: 0,
                metaRefreshDetected: false
            },
            confidence: 0
        };

        // 1. Capture Screenshot (Visual Forensics)
        if (!url.startsWith('file://')) {
            const screenshotBuffer = await page.screenshot({ encoding: 'base64' });
            analysis.screenshot = screenshotBuffer;
        }

        // 2. Infrastructure fingerprinting is limited to validated DNS data.
        // ASN, hosting provider, and country are never guessed.

        // 3. Passive behavioral analysis. The agent observes only; it never submits
        // forms, enters credentials, uses OTPs, or tries to bypass access controls.
        const forms = await page.$$('form');
        const pageSignals = await page.evaluate(() => {
            const interactiveSelector = 'button, a, input, textarea, select, [role="button"]';
            const allInputs = Array.from(document.querySelectorAll('input'));
            const links = Array.from(document.querySelectorAll('a[href]'));
            const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');

            return {
                interactiveElementCount: document.querySelectorAll(interactiveSelector).length,
                passwordFieldCount: document.querySelectorAll('input[type="password"]').length,
                otpFieldCount: allInputs.filter((input) => {
                    const attributes = `${input.name || ''} ${input.id || ''} ${input.placeholder || ''} ${input.autocomplete || ''}`.toLowerCase();
                    return /otp|one-time|verification.?code|two.?factor/.test(attributes);
                }).length,
                hiddenInputCount: document.querySelectorAll('input[type="hidden"]').length,
                downloadLinkCount: links.filter((link) => link.hasAttribute('download') || /\.(exe|msi|apk|dmg|zip|rar|7z|iso)(\?|$)/i.test(link.href)).length,
                metaRefreshDetected: Boolean(metaRefresh)
            };
        });
        pageSignals.attachmentResponseCount = attachmentResponses.length;
        analysis.behavioralSignals = pageSignals;

        if (pageSignals.passwordFieldCount > 0) {
            analysis.hasPasswordFields = true;
        }
        if (pageSignals.otpFieldCount > 0) {
            analysis.reason.push('Page exposes an OTP or verification-code field for review.');
        }
        if (pageSignals.downloadLinkCount > 0 || pageSignals.attachmentResponseCount > 0) {
            analysis.reason.push('Page exposes a direct download or attachment response that requires review.');
        }
        if (pageSignals.metaRefreshDetected || analysis.navigation.redirected) {
            analysis.reason.push('Page uses a redirect or meta refresh; destination should be reviewed.');
        }
        if (forms.length > 0) {
            analysis.hasForms = true;
            if (analysis.hasPasswordFields) {
                analysis.isSuspicious = true;
                analysis.reason.push('Found password input field on a scanned, unverified domain.');
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

        // A brand-like page with no meaningful user-facing interaction is only a
        // review signal. It is not treated as proof of a scam by itself.
        if (analysis.detectedBrand && pageSignals.interactiveElementCount === 0) {
            analysis.reason.push('Brand-like content has no user-facing interactive elements; manual review is recommended.');
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
export async function shutdownBrowserPool() {
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
