# VerifyPulse Accuracy Upgrade Research

## Authoritative sources reviewed

| Source | Reusable detection and validation signal |
|---|---|
| CERT-In, Advisory CIAD-2024-0050 | Phishing and lottery/prize fraud are core Indian cyber-fraud categories to retain in adversarial test coverage. |
| Indian Cybercrime Coordination Centre (I4C), Advisories | The I4C advisories page reports official observations of regulatory/executive impersonation, WhatsApp account takeover using malicious Windows executables, and high-value financial fraud. These patterns support deterministic combinations of authority impersonation, account-takeover pressure, executable downloads, and financial-action requests. |

## Engineering application

The upgrade will use these sources only to derive privacy-safe behavioural signals and synthetic benchmark cases. It will not store victim messages, passwords, OTPs, bank details, phone numbers, or personal identities. Existing official-domain safeguards remain intact; no source turns a domain match into proof that a message sender is authentic.

## References

1. CERT-In, [Advisory CIAD-2024-0050](https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2024-0050).
2. Indian Cybercrime Coordination Centre, [Advisories](https://i4c.mha.gov.in/advisories.aspx).

| NPCI, Fraud Awareness | NPCI warns that QR-code scanning plus UPI PIN entry is for making a payment, not receiving funds. It identifies fake cashback links, QR-code fraud, unknown-app downloads, fake investments, threatening SMS/social messages, and social-engineering abuse. It also advises against sharing debit-card credentials or UPI PIN, using screen-sharing/remote-access apps during financial transactions, and acting while speaking with an unverified third party. |

This supports a narrowly scoped high-risk combination rule for payment-receipt claims paired with QR scanning, UPI PIN entry, collect requests, cashback/reward language, remote-access instructions, or urgency. It also supports balanced benign cases: a transaction confirmation with no action demand must not become a risk verdict solely because it contains UPI terms.

3. National Payments Corporation of India, [Fraud Awareness](https://www.npci.org.in/fraud-awareness).

| RBI, public caution against fictitious offers | RBI states that it does not make unsolicited phone calls or emails asking the public for money or personal information and warns against impersonation by people claiming to be RBI employees. This supports high-risk combinations of claimed RBI authority, unsolicited contact, payment/personal-data request, and urgency. |

4. Reserve Bank of India, [RBI cautions Public Once Again against Fictitious Offers](https://www.rbi.org.in/commonman/English/Scripts/PressReleases.aspx?Id=2440).
