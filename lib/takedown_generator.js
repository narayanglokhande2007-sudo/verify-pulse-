import crypto from 'node:crypto';

export async function generateTakedownNotice(maliciousUrl, brandName = "our protected client") {
    try {
        let urlObj;
        try {
            urlObj = new URL(maliciousUrl.startsWith('http') ? maliciousUrl : 'https://' + maliciousUrl);
        } catch (e) {
            return { error: "Invalid URL format." };
        }
        
        const domain = urlObj.hostname;

        // Use Google DoH API to retrieve Nameservers and Abuse routing without blocking
        const dnsRes = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`);
        const dnsData = await dnsRes.json();
        
        let abuseEmail = `abuse@${domain}`; // Fallback
        let hostingProvider = "Unknown Registrar / Hosting Provider";
        let nsRecords = [];

        if (dnsData.Answer) {
            nsRecords = dnsData.Answer.map(a => String(a.data).toLowerCase());
            
            // Map common Nameservers to their official Abuse Desks
            if (nsRecords.some(ns => ns.includes('cloudflare'))) { abuseEmail = 'abuse@cloudflare.com'; hostingProvider = 'Cloudflare'; }
            else if (nsRecords.some(ns => ns.includes('domaincontrol'))) { abuseEmail = 'abuse@godaddy.com'; hostingProvider = 'GoDaddy'; }
            else if (nsRecords.some(ns => ns.includes('hostinger'))) { abuseEmail = 'abuse@hostinger.com'; hostingProvider = 'Hostinger'; }
            else if (nsRecords.some(ns => ns.includes('namecheap'))) { abuseEmail = 'abuse@namecheap.com'; hostingProvider = 'Namecheap'; }
            else if (nsRecords.some(ns => ns.includes('awsdns'))) { abuseEmail = 'trustandsafety@support.aws.com'; hostingProvider = 'Amazon Web Services'; }
            else if (nsRecords.some(ns => ns.includes('bluehost'))) { abuseEmail = 'legal@bluehost.com'; hostingProvider = 'Bluehost'; }
            else if (nsRecords.some(ns => ns.includes('googledomains'))) { abuseEmail = 'registrar-abuse@google.com'; hostingProvider = 'Google Domains'; }
        }

        const emailSubject = `URGENT: Phishing & Fraud Takedown Request for [${domain}]`;
        const emailBody = `Dear Abuse and Security Team at ${hostingProvider},

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

        const evidenceDigest = crypto.createHash('sha256').update(`${maliciousUrl}:${domain}:${hostingProvider}:${emailBody}`).digest('hex');

        return {
            success: true,
            domain,
            hostingProvider,
            abuseEmail,
            emailSubject,
            emailBody,
            evidenceDossier: {
                evidenceDigestSha256: evidenceDigest,
                threatClassification: "Financial Phishing / Brand Impersonation",
                dnsNameservers: nsRecords,
                protocolStandard: "RFC 2142 Abuse Mailbox Protocol",
                timestamp: new Date().toISOString()
            },
            status: "READY_FOR_DISPATCH"
        };
    } catch (error) {
        return { success: false, error: "Failed to generate takedown notice. DNS lookup failed." };
    }
}