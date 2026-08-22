# Contributing to VerifyPulse

Thank you for helping improve VerifyPulse. The project handles scam-risk guidance, so a contribution must make the product more useful **without** overstating certainty, weakening privacy, or creating risk for users.

## Before you begin

Use public GitHub issues for reproducible bugs, documentation corrections, and clearly scoped improvements. Do not post a security vulnerability in an issue; follow the private route in [SECURITY.md](SECURITY.md). Do not use issues to paste raw suspicious URLs, user messages, OTPs, credentials, payment information, personal data, or unreviewed harmful files.

For local checks, use Node.js 18 or later:

```bash
git clone https://github.com/narayanglokhande2007-sudo/verify-pulse-.git
cd verify-pulse-
npm ci --ignore-scripts
npm test
```

## Contribution principles

| Principle | What it means in practice |
|---|---|
| **Privacy first** | Never add secrets, API keys, personal data, raw user scan inputs, or the private benchmark dataset to the repository. |
| **Evidence before claims** | Do not add guaranteed detection, fixed accuracy, certification, uptime, or competitor-comparison claims without independently verifiable evidence. |
| **Fail safely** | A provider outage or missing evidence must not become a misleading SAFE result. |
| **Small and testable** | Keep each change focused, explain the user-safety benefit, and add or update a test when behaviour changes. |
| **India-relevant and inclusive** | Keep public guidance clear for Indian scam patterns while avoiding assumptions about a specific bank, person, or transaction. |

## Suggested process

1. Check existing issues and documentation so the work is not duplicated.
2. Describe the problem, expected result, and possible safety or privacy effect.
3. Make the smallest practical change. Preserve existing working features unless a replacement is explicitly justified.
4. Run `npm test` before proposing the change.
5. In a pull request, explain what changed, what was tested, and any limitation that remains.

## Areas where feedback is useful

Responsible feedback is especially useful for clear scam-safety wording, accessible Hindi/English explanations, documentation accuracy, input validation, test coverage, safe degraded behaviour, and developer documentation.

By contributing, you agree not to use this repository to distribute harmful links, phishing material, malware, private data, or deceptive promotional content.
