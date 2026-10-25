import crypto from 'node:crypto';

const NAMESERVER_HOSTING_MAP = [
    { pattern: 'cloudflare', provider: 'Cloudflare', email: 'abuse@cloudflare.com' },
    { pattern: 'domaincontrol', provider: 'GoDaddy', email: 'abuse@godaddy.com' },
    { pattern: 'godaddy', provider: 'GoDaddy', email: 'abuse@godaddy.com' },
    { pattern: 'hostinger', provider: 'Hostinger', email: 'abuse@hostinger.com' },
    { pattern: 'namecheap', provider: 'Namecheap', email: 'abuse@namecheap.com' },
    { pattern: 'registrar-servers', provider: 'Namecheap', email: 'abuse@namecheap.com' },
    { pattern: 'awsdns', provider: 'Amazon Web Services', email: 'trustandsafety@support.aws.com' },
    { pattern: 'amazon', provider: 'Amazon Web Services', email: 'trustandsafety@support.aws.com' },
    { pattern: 'bluehost', provider: 'Bluehost', email: 'legal@bluehost.com' },
    { pattern: 'googledomains', provider: 'Google Domains', email: 'registrar-abuse@google.com' },
    { pattern: 'google', provider: 'Google Cloud Platform', email: 'googlecloud-abuse@google.com' },
    { pattern: 'digitalocean', provider: 'DigitalOcean', email: 'abuse@digitalocean.com' },
    { pattern: 'hetzner', provider: 'Hetzner Online', email: 'abuse@hetzner.com' },
    { pattern: 'ovh', provider: 'OVHcloud', email: 'abuse@ovh.net' },
    { pattern: 'azure', provider: 'Microsoft Azure', email: 'abuse@microsoft.com' },
    { pattern: 'fastly', provider: 'Fastly', email: 'abuse@fastly.com' },
    { pattern: 'akamai', provider: 'Akamai Technologies', email: 'abuse@akamai.com' },
    { pattern: 'akam', provider: 'Akamai Technologies', email: 'abuse@akamai.com' },
    { pattern: 'porkbun', provider: 'Porkbun', email: 'abuse@porkbun.com' },
    { pattern: 'dynadot', provider: 'Dynadot', email: 'abuse@dynadot.com' },
    { pattern: 'namesilo', provider: 'NameSilo', email: 'abuse@namesilo.com' },
    { pattern: 'bigrock', provider: 'BigRock India', email: 'abuse@bigrock.com' },
    { pattern: 'hostgator', provider: 'HostGator', email: 'abuse@hostgator.com' },
    { pattern: 'siteground', provider: 'SiteGround', email: 'abuse@siteground.com' },
    { pattern: 'tencent', provider: 'Tencent Cloud', email: 'abuse@tencent.com' },
    { pattern: 'alibabadns', provider: 'Alibaba Cloud', email: 'abuse@alibabacloud.com' },
    { pattern: 'alidns', provider: 'Alibaba Cloud', email: 'abuse@alibabacloud.com' },
    { pattern: 'vultr', provider: 'Vultr', email: 'abuse@vultr.com' },
    { pattern: 'linode', provider: 'Linode / Akamai', email: 'abuse@linode.com' },
    { pattern: 'contabo', provider: 'Contabo', email: 'abuse@contabo.com' },
    { pattern: 'leaseweb', provider: 'Leaseweb', email: 'abuse@leaseweb.com' }
];

const DIRECT_PLATFORM_MAP = [
    { pattern: 't.me', provider: 'Telegram Messenger', email: 'abuse@telegram.org' },
    { pattern: 'telegram.me', provider: 'Telegram Messenger', email: 'abuse@telegram.org' },
    { pattern: 'mega.nz', provider: 'Mega Cloud Storage', email: 'abuse@mega.nz' },
    { pattern: 'mediafire.com', provider: 'MediaFire', email: 'abuse@mediafire.com' },
    { pattern: 'drive.google.com', provider: 'Google Drive', email: 'googlecloud-abuse@google.com' },
    { pattern: 'firebasestorage.googleapis.com', provider: 'Google Firebase Storage', email: 'googlecloud-abuse@google.com' },
    { pattern: 's3.amazonaws.com', provider: 'AWS S3 Storage', email: 'trustandsafety@support.aws.com' },
    { pattern: 'github.com', provider: 'GitHub', email: 'abuse@github.com' }
];

export async function generateTakedownNotice(maliciousUrl, brandName = "our protected client", options = {}) {
    try {
        let urlObj;
        try {
            urlObj = new URL(maliciousUrl.startsWith('http') ? maliciousUrl : 'https://' + maliciousUrl);
        } catch (e) {
            return { error: "Invalid URL format." };
        }
        
        const domain = urlObj.hostname;
        const lowerUrl = maliciousUrl.toLowerCase();
        const lowerDomain = domain.toLowerCase();

        // 1. Detect if target is an APK / Rogue App download
        const isApk = (
            lowerUrl.endsWith('.apk') ||
            lowerUrl.includes('.apk?') ||
            lowerUrl.includes('/apk/') ||
            options.threatType === 'ROGUE_APK' ||
            Boolean(options.apkDetails)
        );

        // 2. Resolve DNS Nameservers (Enrichment only)
        let dnsData = {};
        let dnsLookupStatus = 'UNAVAILABLE';

        if (options.dnsData) {
            dnsData = options.dnsData;
            dnsLookupStatus = 'COMPLETED';
        } else if (options.mockNameservers) {
            dnsData = { Answer: options.mockNameservers.map(ns => ({ data: ns })) };
            dnsLookupStatus = 'MOCKED';
        } else {
            try {
                const dnsRes = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`, {
                    signal: AbortSignal.timeout(3000)
                });
                if (dnsRes.ok) {
                    dnsData = await dnsRes.json();
                    dnsLookupStatus = 'COMPLETED';
                }
            } catch {}
        }
        
        let abuseEmail = `abuse@${domain}`; // RFC 2142 Fallback
        let hostingProvider = "Unknown Registrar / Hosting Provider";
        let nsRecords = [];

        // Check Direct Platform match first (e.g. Telegram, Mega, MediaFire, S3)
        const directMatch = DIRECT_PLATFORM_MAP.find(p => lowerDomain === p.pattern || lowerDomain.endsWith('.' + p.pattern));
        if (directMatch) {
            hostingProvider = directMatch.provider;
            abuseEmail = directMatch.email;
        } else if (dnsData.Answer) {
            nsRecords = dnsData.Answer.map(a => String(a.data).toLowerCase());
            
            // Map common Nameservers to their verified Abuse Desks
            for (const mapItem of NAMESERVER_HOSTING_MAP) {
                if (nsRecords.some(ns => ns.includes(mapItem.pattern))) {
                    hostingProvider = mapItem.provider;
                    abuseEmail = mapItem.email;
                    break;
                }
            }
        }

        // 3. Prepare Takedown Subject and Body tailored to threat type
        let emailSubject = '';
        let emailBody = '';
        const apkDetails = options.apkDetails || null;
        let signatureVerdict = null;

        if (apkDetails && apkDetails.officialSha256 && apkDetails.suspectSha256) {
            const isMatch = apkDetails.officialSha256.toLowerCase().replace(/[^a-f0-9]/g, '') ===
                            apkDetails.suspectSha256.toLowerCase().replace(/[^a-f0-9]/g, '');
            signatureVerdict = isMatch
                ? 'UNAUTHORIZED_DISTRIBUTION (Official binary leaked or mirrored outside authorized app store)'
                : 'UNAUTHORIZED_SIGNATURE_MISMATCH (Rogue Impersonation / Trojanized Modified Sideload APK)';
        }

        if (isApk) {
            emailSubject = `URGENT: Rogue Android APK Impersonation Takedown Request for [${domain}]`;
            emailBody = `Dear Abuse and Security Team at ${hostingProvider},

We are writing on behalf of VerifyPulse Threat Intelligence to officially report an unauthorized and malicious Android APK application hosted on your infrastructure.

Malicious APK URL: ${maliciousUrl}
Targeted Protected Entity: ${brandName}
Threat Type: Rogue Android Application / Malicious APK Impersonation
Statutory Framework: 
  - Information Technology Act 2000, Section 66D (Cheating by personation using computer resource)
  - Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021, Rule 3(1)(d)
  - CERT-In Financial Fraud Incident Reporting Protocol

Forensic Evidence Log:
Our automated APK signature engine has flagged this file for brand impersonation and financial fraud risk.${apkDetails ? `
Package Name: ${apkDetails.packageName || 'Unknown'}
Official App Certificate (SHA-256): ${apkDetails.officialSha256 || 'N/A'}
Suspect Binary Certificate (SHA-256): ${apkDetails.suspectSha256 || 'N/A'}
Cryptographic Verdict: ${signatureVerdict || 'ROUGE_APK_DETECTED'}` : ''}

Requested Action:
In accordance with Rule 3(1)(d) of the IT Intermediary Rules, 2021, we formally demand the immediate takedown and disabling of access to this malicious APK package to prevent catastrophic financial loss to retail borrowers.

Please acknowledge receipt and confirm suspension.

Best regards,
VerifyPulse Automated Takedown Operations
Emergency CERT-In Liaison Desk: abuse-reports@cert-in.org.in
https://www.verify-pulse.com`;
        } else {
            emailSubject = `URGENT: Phishing & Fraud Takedown Request for [${domain}]`;
            emailBody = `Dear Abuse and Security Team at ${hostingProvider},

We are writing to you on behalf of VerifyPulse Threat Intelligence to officially report a high-risk phishing and financial fraud domain hosted on your network infrastructure.

Malicious URL: ${maliciousUrl}
Targeted Entity: ${brandName}
Threat Type: Social Engineering / Financial Fraud / Phishing

Evidence Log:
Our automated heuristic engine has flagged this URL for credential theft and scam-risk behaviors. Continuing to host this domain violates international anti-phishing policies and your Terms of Service.

Requested Action:
We request the immediate suspension of this domain or removal of the malicious content to prevent further financial loss to innocent users.

Please confirm once the domain has been suspended.

Best regards,
VerifyPulse Automated Takedown System
https://www.verify-pulse.com`;
        }

        const evidenceDigest = crypto.createHash('sha256').update(`${maliciousUrl}:${domain}:${hostingProvider}:${emailBody}`).digest('hex');

        return {
            success: true,
            domain,
            hostingProvider,
            abuseEmail,
            emailSubject,
            emailBody,
            isApk,
            apkDetails: apkDetails ? {
                ...apkDetails,
                signatureVerdict
            } : null,
            evidenceDossier: {
                evidenceDigestSha256: evidenceDigest,
                threatClassification: isApk
                    ? "Rogue Android Application / Malicious APK Impersonation"
                    : "Financial Phishing / Brand Impersonation",
                dnsNameservers: nsRecords,
                dnsLookupStatus,
                protocolStandard: "RFC 2142 Abuse Mailbox Protocol",
                statutoryFramework: isApk
                    ? ["IT Act 2000 Section 66D", "IT Intermediary Rules 2021 Rule 3(1)(d)", "CERT-In Financial Fraud Protocol"]
                    : ["IT Act 2000 Section 79", "RFC 2142 Abuse Protocol"],
                timestamp: new Date().toISOString()
            },
            status: "READY_FOR_DISPATCH"
        };
    } catch (error) {
        return { success: false, error: "Failed to generate takedown notice. DNS lookup failed." };
    }
}