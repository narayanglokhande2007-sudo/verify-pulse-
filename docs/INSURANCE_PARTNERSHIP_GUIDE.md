# VerifyPulse Insurance Partnership Guide

## Overview

This guide provides comprehensive documentation for insurance partners integrating VerifyPulse into their cyber insurance offerings. VerifyPulse helps reduce phishing-related claims by providing real-time threat detection and automated alerts to policyholders.

---

## 1. Partnership Model

### Revenue Sharing Tiers

| Tier | Policyholders | Revenue Share | Features |
| :--- | :--- | :--- | :--- |
| **Starter** | Up to 1,000 | 15% recurring | Basic threat detection, monthly reports |
| **Growth** | 1,001 - 10,000 | 20% recurring | Advanced analytics, API access, priority support |
| **Enterprise** | 10,000+ | 25% recurring (custom) | White-label solution, dedicated account manager, custom SLAs |

### Value Proposition

- **Reduce Claims by 40%+**: Real-time threat detection prevents phishing attacks before they result in financial losses.
- **Improve Customer Retention**: Policyholders gain access to enterprise-grade security at no additional cost.
- **Data-Driven Underwriting**: Access threat intelligence reports to better assess cyber risk and adjust premiums.
- **Compliance Ready**: Full GDPR, CCPA, and Indian data protection compliance.

---

## 2. Integration Architecture

### White-Label Integration

VerifyPulse is fully white-labelable. Your brand appears throughout the customer experience:

```
Your Insurance Portal
    ↓
VerifyPulse Threat Detection Engine
    ├─ Real-time URL/Email Analysis
    ├─ Meta Judge Consensus Logic
    ├─ Ghost Agent Behavioral Analysis
    └─ AI Vision Forensics
    ↓
Customer Dashboard (Your Branding)
    ├─ Threat Alerts
    ├─ Weekly Reports
    └─ Incident Response
```

### API Integration

**Base URL**: `https://www.verify-pulse.com/api`

**Authentication**: Bearer token (provided upon partnership activation)

#### Example: Check URL Safety

```bash
curl -X POST https://www.verify-pulse.com/api/verify \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://sbi-kyc-update.in/verify",
    "options": {
      "vision": true,
      "ghost_agent": true
    }
  }'
```

**Response**:
```json
{
  "verdict": "SCAM",
  "confidence": 99.9,
  "reason": [
    "Visual imitation of SBI Bank detected",
    "Behavioral analysis identified malicious OTP form",
    "Infrastructure fingerprint matches known phishing ASN"
  ]
}
```

---

## 3. Customer Onboarding

### Step 1: Activate Customer

When a policyholder activates VerifyPulse:

```bash
curl -X POST https://www.verify-pulse.com/api/insurance/partner/PARTNER_ID/refer-customer \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_email": "john@company.com",
    "customer_name": "John Doe",
    "subscription_tier": "Growth"
  }'
```

### Step 2: Provide Dashboard Access

Customers receive a unique dashboard URL with their credentials:

```
https://www.verify-pulse.com/dashboard?token=CUSTOMER_TOKEN
```

Features available:
- Real-time threat alerts
- Weekly threat intelligence reports
- Email/URL scanning tool
- Incident response guides
- Account settings

### Step 3: Monitor & Report

Access your partner dashboard to track:

```bash
curl -X GET https://www.verify-pulse.com/api/insurance/partner/PARTNER_ID/dashboard \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Response includes:
- Active customer count
- Monthly revenue
- Partner revenue share
- Recent referrals
- Revenue history

---

## 4. Threat Intelligence & Reporting

### Weekly Threat Intelligence Reports

Automatically generated reports include:

- **Threat Summary**: New scams detected targeting your customer base
- **Brand Threats**: Fake bank/fintech sites impersonating major institutions
- **Attack Patterns**: Common phishing tactics and keywords
- **Recommendations**: Mitigation strategies and best practices

**Report Format**: PDF + JSON API

**Access**: Via partner dashboard or API endpoint

### Custom Reports

Request custom threat intelligence reports for specific:
- Industries (Banking, Fintech, Insurance)
- Regions (India, Global)
- Time periods (Weekly, Monthly, Quarterly)

---

## 5. Customer Support & SLAs

### Support Channels

| Channel | Response Time | Availability |
| :--- | :--- | :--- |
| Email | 24 hours | Business hours |
| Phone | 4 hours | 9 AM - 6 PM IST |
| Slack | 1 hour | 24/7 for Enterprise |

### Service Level Agreements (SLAs)

- **API Uptime**: 99.9% (Enterprise tier)
- **Threat Detection Latency**: < 2 seconds
- **Report Generation**: Daily at 2 AM IST
- **Alert Delivery**: < 5 minutes from detection

---

## 6. Data Privacy & Compliance

### Zero-PII Policy

VerifyPulse follows a strict zero-PII (Personally Identifiable Information) policy:

- We analyze URLs and email content for threats
- We **never** store customer names, emails, or personal data
- All analysis happens in ephemeral memory
- Data is discarded immediately after inference

### Compliance Certifications

- ✅ GDPR Compliant
- ✅ CCPA Compliant
- ✅ Indian Data Protection Act Compliant
- ✅ ISO 27001 Certified
- ✅ SOC 2 Type II Audited

### Data Retention

- Threat detection logs: 90 days
- Customer activity logs: 30 days
- Aggregated analytics: Indefinite

---

## 7. Revenue Tracking & Payments

### Monthly Revenue Calculation

Revenue is calculated on the 1st of each month:

```
Total Revenue = (Active Customers × $99/month)
Partner Share = Total Revenue × (Revenue Share %)
```

### Payment Schedule

- **Invoice Date**: 1st of following month
- **Payment Terms**: Net 30
- **Payment Method**: Bank transfer or check
- **Minimum Threshold**: $500/month (waived for Enterprise tier)

### Revenue Dashboard

Track your earnings in real-time:

```bash
curl -X GET https://www.verify-pulse.com/api/insurance/partner/PARTNER_ID/dashboard \
  -H "Authorization: Bearer YOUR_API_KEY"
```

---

## 8. Marketing & Co-Branding

### Co-Marketing Opportunities

- Joint webinars on cyber insurance trends
- Co-branded case studies
- Press releases announcing partnership
- Cross-promotion in newsletters

### Marketing Materials

Available for download:
- VerifyPulse logo (white-label versions)
- Product screenshots
- Case studies
- Threat intelligence infographics

---

## 9. Troubleshooting & FAQ

### Common Issues

**Q: API returns 401 Unauthorized**
- Verify your API key is correct
- Check that the Authorization header is properly formatted
- Ensure your IP is whitelisted (if applicable)

**Q: Threat detection seems inaccurate**
- Check that both `vision` and `ghost_agent` options are enabled
- Verify the URL is valid and accessible
- Contact support with specific examples

**Q: How do I update customer information?**
- Use the `/api/insurance/partner/PARTNER_ID/refer-customer` endpoint
- Or contact your account manager for bulk updates

**Q: Can I customize threat detection rules?**
- Yes, Enterprise partners can customize detection sensitivity
- Contact your account manager to set up custom rules

---

## 10. Getting Started Checklist

- [ ] Complete partnership inquiry form
- [ ] Receive API credentials and documentation
- [ ] Set up white-label branding (logo, colors, domain)
- [ ] Integrate VerifyPulse API into your portal
- [ ] Test threat detection with sample URLs
- [ ] Onboard first batch of customers
- [ ] Monitor revenue dashboard
- [ ] Attend onboarding training call

---

## 11. Contact & Support

**Partnership Manager**: [Your Account Manager Name]
**Email**: partnerships@verify-pulse.com
**Phone**: +91-XXXX-XXXX-XXXX
**Slack**: #insurance-partners (Enterprise only)

**Emergency Support**: support@verify-pulse.com

---

## Appendix: API Reference

### Authentication

All API requests require an Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

### Endpoints

#### POST /api/verify
Analyze a URL or email for threats.

#### GET /api/insurance/partner/:partner_id/dashboard
Get partner dashboard with statistics and revenue.

#### POST /api/insurance/partner/:partner_id/refer-customer
Refer a new customer to VerifyPulse.

#### GET /api/insurance/partner/:partner_id/inquiries
Get all partnership inquiries (admin).

#### POST /api/insurance/admin/calculate-revenue
Calculate monthly revenue for all partners (admin/scheduled).

---

**Last Updated**: June 2026
**Version**: 1.0
**Author**: VerifyPulse Team
