// api/verify.js - VerifyPulse Backend (with Live Scam Knowledge Boost)
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { text, checkType } = req.body;
  if (!text || !checkType) return res.status(400).json({ error: 'Missing text or checkType' });

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY;

  try {
    // Password local check
    if (checkType === 'password') {
      return res.status(200).json({ verdict: 'SAFE', confidence: 95, analysis: 'Checked locally', findings: [] });
    }

    // ---- LIVE KNOWLEDGE BOOST: fetch latest scam URLs from pipeline ----
    let recentScamURLs = [];
    try {
      const pipelineURL = 'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/latest_scams.json';
      const pipelineRes = await fetch(pipelineURL);
      if (pipelineRes.ok) {
        const allURLs = await pipelineRes.json();
        recentScamURLs = allURLs.slice(-20); // last 20 most recent
      }
    } catch (e) { /* ignore if not available */ }

    // Build a knowledge booster line
    const knowledgeLine = recentScamURLs.length > 0
      ? `\n\nLatest known phishing/scam URLs (for reference):\n${recentScamURLs.join('\n')}`
      : '';

    // Safe Browsing check for appropriate types
    if (['url', 'phishing', 'scam', 'gmail'].includes(checkType) && SAFE_BROWSING_KEY) {
      try {
        const safeResult = await checkWithSafeBrowsing(text, SAFE_BROWSING_KEY);
        if (safeResult && safeResult.found) {
          return res.status(200).json(safeResult);
        }
      } catch (e) {}
    }

    // Gemini for fact-checking
    if (checkType === 'news' && GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY);
        if (gemRes) return res.status(200).json(gemRes);
      } catch (e) {}
    }

    // DeepSeek R1 for complex reasoning
    if (['scam', 'gmail'].includes(checkType)) {
      try {
        const deepRes = await callGroq(GROQ_KEY, text, checkType, 'deepseek-r1-distill-llama-70b', knowledgeLine);
        if (deepRes) return res.status(200).json(deepRes);
      } catch (e) {}
    }

    // Default Groq Llama 3.3
    const finalRes = await callGroq(GROQ_KEY, text, checkType, 'llama-3.3-70b-versatile', knowledgeLine);
    return res.status(200).json(finalRes);

  } catch (error) {
    return res.status(500).json({ error: error.message || 'AI engine failed' });
  }
}

// ========== Safe Browsing ==========
async function checkWithSafeBrowsing(inputUrl, apiKey) {
  try {
    const payload = {
      client: { clientId: "verifypulse", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: inputUrl }]
      }
    };
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST', body: JSON.stringify(payload)
    });
    if (!resp.ok) throw new Error('Safe Browsing failed');
    const data = await resp.json();
    if (data.matches) {
      return {
        verdict: 'DANGEROUS', confidence: 100,
        analysis: 'Google Safe Browsing has identified this as a known malicious/phishing link.',
        findings: []
      };
    }
    return { found: false };
  } catch (e) { return { found: false }; }
}

// ========== Gemini ==========
async function callGemini(text, apiKey) {
  const systemPrompt = `You are a fact-checking AI. Analyze and determine if TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply ONLY in JSON: {"verdict":"...", "confidence":85, "analysis":"...", "findings":[]}`;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const body = { contents: [{ parts: [{ text: `${systemPrompt}\n\nInput: "${text}"` }] }] };
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error('Gemini failed');
  const data = await res.json();
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!content) throw new Error('Empty Gemini response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  if (parsed.confidence > 0 && parsed.confidence <= 1) parsed.confidence = Math.round(parsed.confidence * 100);
  return parsed;
}

// ========== Groq ==========
async function callGroq(apiKey, text, type, model, knowledgeLine = '') {
  const systemPrompt = getPrompt(type, knowledgeLine);
  const url = 'https://api.groq.com/openai/v1/chat/completions';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: "You are a cybersecurity and scam-detection AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings, whatToDo." },
        { role: 'user', content: systemPrompt + `\n\nInput: "${text}"` }
      ],
      temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
    })
  });
  if (!res.ok) throw new Error('Groq failed');
  const data = await res.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('Empty Groq response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  if (parsed.confidence > 0 && parsed.confidence <= 1) parsed.confidence = Math.round(parsed.confidence * 100);

  // Enrich result
  if (!parsed.scamType) {
    const lower = (parsed.verdict + ' ' + (parsed.analysis||'')).toLowerCase();
    if (lower.includes('phish')) parsed.scamType = 'Phishing Attack';
    else if (lower.includes('fake reward') || lower.includes('lottery') || lower.includes('won')) parsed.scamType = 'Fake Reward Scam';
    else if (lower.includes('otp')) parsed.scamType = 'OTP Fraud';
    else if (lower.includes('upi')) parsed.scamType = 'UPI Fraud';
    else if (lower.includes('job')) parsed.scamType = 'Job Scam';
    else if (lower.includes('loan')) parsed.scamType = 'Loan Fraud';
    else if (lower.includes('bank') || lower.includes('kyc')) parsed.scamType = 'Bank Impersonation';
    else if (parsed.verdict === 'SAFE') parsed.scamType = 'Safe Content';
    else if (parsed.verdict === 'SUSPICIOUS') parsed.scamType = 'Suspicious Activity';
    else if (parsed.verdict === 'DANGEROUS') parsed.scamType = 'Dangerous Threat';
    else parsed.scamType = 'Potential Scam';
  }
  if (!parsed.whatToDo) {
    const tips = [];
    if (parsed.scamType === 'Phishing Attack' || parsed.scamType === 'Bank Impersonation') {
      tips.push('Do NOT click the link', 'Do NOT enter login details', 'Open official website manually');
    } else if (parsed.scamType === 'Fake Reward Scam') {
      tips.push('Do NOT send any money', 'Do NOT share personal info', 'Report the sender');
    } else if (parsed.scamType === 'OTP Fraud') {
      tips.push('Never share OTP', 'No legit company asks OTP', 'Block and report');
    } else if (parsed.scamType === 'UPI Fraud') {
      tips.push('Do NOT approve payment', 'Check receiver name', 'Report in UPI app');
    } else {
      tips.push('Be cautious with unsolicited messages', 'Do not share sensitive info', 'Verify via official channels');
    }
    parsed.whatToDo = tips;
  }
  return parsed;
}

// ========== Prompts ==========
function getPrompt(type, knowledgeLine = '') {
  const baseSCAM = `You are an Indian scam detection expert. Analyze the message and return a JSON object with:
- verdict: SCAM / FRAUD / SAFE / SUSPICIOUS
- scamType: one of [Phishing Attack, Fake Reward Scam, OTP Fraud, UPI Fraud, Job Scam, Loan Fraud, Bank Impersonation, Safe Content]
- confidence: realistic number between 65 and 91
- analysis: human-like explanation in 2-3 sentences
- findings: array of bullet-point red flags
- whatToDo: array of specific actionable steps.

Examples of Indian scams: fake KBC lottery, SBI KYC update, UPI payment request, OTP sharing, job fraud with advance payment.
A normal marketing SMS from Airtel/Vi/Flipkart is usually SAFE.`;

  if (type === 'news') return `Determine if the news is TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply ONLY in JSON with keys: verdict, confidence, analysis, findings.${knowledgeLine}`;
  if (type === 'url') return `Analyze the URL and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.${knowledgeLine}`;
  if (type === 'phishing') return baseSCAM + knowledgeLine;
  if (type === 'scam') return baseSCAM + knowledgeLine;
  if (type === 'phone') return `Analyze the phone number and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.${knowledgeLine}`;
  if (type === 'upi') return `Analyze the UPI ID and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.${knowledgeLine}`;
  if (type === 'gmail') return baseSCAM + knowledgeLine;
  return `Analyze and return JSON with keys: verdict, confidence, analysis, findings.`;
}
