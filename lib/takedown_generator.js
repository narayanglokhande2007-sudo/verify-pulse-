// lib/takedown_generator.js
// VerifyPulse Tier 2: Automated Legal Takedown Generator
// Uses Serverless-safe DNS-over-HTTPS to find the host registrar and generate abuse reports.

export async function generateTakedownNotice(maliciousUrl, brandName = "our protected client") {
    try {
        let urlObj;
        try {
            urlObj = new URL(maliciousUrl.startsWith('http') ? maliciousUrl : 'https://' + maliciousUrl);
        } catch (e) {
            return { error: "Invalid URL format." };
        }
        
        const domain = urlObj.hostname;

        // Deep Analysis Trick: Use Google's free DoH (DNS over HTTPS) API 
        // to get Nameservers without needing a paid WHOIS API or blocked TCP ports on Vercel.
        const dnsRes = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`);
        const dnsData = await dnsRes.json();
        
        let abuseEmail = `abuse@${domain}`; // Fallback
        let hostingProvider = "Unknown Registrar / Hosting Provider";

        if (dnsData.Answer) {
            const nsRecords = dnsData.Answer.map(a => String(a.data).toLowerCase());
            
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

        return {
            success: true,
            domain,
            hostingProvider,
            abuseEmail,
            emailSubject,
            emailBody,
            status: "READY_FOR_DISPATCH"
        };
    } catch (error) {
        return { success: false, error: "Failed to generate takedown notice. DNS lookup failed." };
    }
}