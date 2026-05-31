# VerifyPulse - Core Architecture & Immutable Rules

This file serves as the permanent memory bank for the VerifyPulse project. 
**ANY FUTURE AI WORKING ON THIS PROJECT MUST STRICTLY OBEY THESE RULES.**

## 1. The Immutable UI/UX
- **Aesthetic:** Premium White and Bright Blue.
- **Rule:** Do not change the core color palette. Do not add TailwindCSS unless explicitly instructed to overwrite the vanilla CSS. The UI must remain fast, glassmorphic, and clean.

## 2. The Multi-Layer AI Fallback System (DO NOT OVERWRITE)
The backend (`api/verify.js`) contains a perfectly optimized, crash-proof pipeline. If making changes, **DO NOT REMOVE** these layers:
1. **The 200+ Trusted Domain Whitelist:** `isTrustedMessage()` mathematically prevents spoofing.
2. **The Text-Only Whitelist:** Official government/brand alerts (without suspicious links/words) are instantly marked SAFE.
3. **Google Safe Browsing:** Direct malware cross-checking before AI.
4. **Primary AI:** Groq (Llama 3.3 70B) for lightning-fast responses.
5. **The Meta-AI Council:** 10 parallel OpenRouter/HuggingFace models running behind a strict **4.5-second timer**. Valid responses are synthesized by a Master Meta-Judge. 
6. **Ultimate Fallback:** Gemini / DeepSeek safety nets.

## 3. The AI Prompt Laws (DO NOT DELETE)
The `baseSCAM` prompt inside `getPrompt()` must permanently retain the **OFFICIAL COMMUNICATION LAWS OF INDIA**:
- Banks never send bit.ly links for KYC.
- Official entities never ask for `.apk` downloads over WhatsApp.
- Police/CBI/TRAI never ask for UPI/Crypto to prevent "Digital Arrest".
- Income Tax Dept never asks for PIN/CVV via SMS.
- Government Heat Wave / Weather alerts are ALWAYS SAFE.

## 4. The 100% Automated Data Pipeline
- **File:** `pipeline/fetch_indian_bulk_scams.py`
- **Execution:** Runs via GitHub Actions (`.github/workflows/daily_scam_fetch.yml`) every day at Midnight UTC (5:30 AM IST).
- **Rule:** It fetches from 12 global threat feeds, forcefully filters out foreign scams, deduplicates, and saves *only Indian* scams.
- **RAG (Automatic Training):** The frontend live-fetches `latest_scams.json` and injects it into the AI prompt. Do not break this connection; it is the source of the automatic daily AI training.
