import json
import os

# 1. Load latest scraped URLs
latest_path = 'pipeline/daily-data/latest_scams.json'
if os.path.exists(latest_path):
    with open(latest_path, 'r', encoding='utf-8') as f:
        latest_urls = json.load(f)
else:
    latest_urls = []

# 2. Load original scam messages (if available)
original_path = 'clean_spam.json'
if os.path.exists(original_path):
    with open(original_path, 'r', encoding='utf-8') as f:
        original_messages = json.load(f)
else:
    original_messages = []

# 3. Combine and deduplicate
all_items = list(set(original_messages + latest_urls))

# 4. Create JSONL in Alpaca format (system, user, assistant)
system_prompt = """You are an Indian scam detection expert. Analyze the message/URL and return a JSON object with:
- verdict: SCAM / FRAUD / SAFE / SUSPICIOUS
- scamType: one of [Phishing Attack, Fake Reward Scam, OTP Fraud, UPI Fraud, Job Scam, Loan Fraud, Bank Impersonation, Safe Content]
- confidence: realistic number between 65 and 91
- analysis: human-like explanation in 2-3 sentences
- findings: array of bullet-point red flags
- whatToDo: array of specific actionable steps."""

jsonl_lines = []
for item in all_items:
    if isinstance(item, str):
        if item.startswith('http'):
            model_response = json.dumps({
                "verdict": "DANGEROUS",
                "scamType": "Phishing Attack",
                "confidence": 100,
                "analysis": "This URL is a known phishing/scam link from our threat intelligence feed.",
                "findings": ["Verified scam URL"],
                "whatToDo": ["Do not visit this link", "Report if you received it"]
            })
        else:
            model_response = json.dumps({
                "verdict": "SCAM",
                "scamType": "Potential Scam",
                "confidence": 85,
                "analysis": "This text contains patterns commonly seen in Indian scam messages.",
                "findings": ["Suspicious content"],
                "whatToDo": ["Do not respond", "Verify via official channels"]
            })

        jsonl_lines.append(json.dumps({
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": item},
                {"role": "assistant", "content": model_response}
            ]
        }, ensure_ascii=False))

output_file = 'pipeline/daily-data/weekly_scam_data.jsonl'
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w', encoding='utf-8') as f:
    for line in jsonl_lines:
        f.write(line + '\n')

print(f"✅ Weekly training data created: {len(jsonl_lines)} examples")
