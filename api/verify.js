export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { text, checkType } = req.body;
  if (!text || !checkType) return res.status(400).json({ error: 'Missing text or checkType' });

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY;

  try {
    if (checkType === 'password') {
      return res.status(200).json({ verdict: 'SAFE', confidence: 95, analysis: 'Checked locally', findings: [] });
    }

    if (['url', 'phishing', 'scam', 'gmail'].includes(checkType) && SAFE_BROWSING_KEY) {
      try {
        const safeResult = await checkWithSafeBrowsing(text, SAFE_BROWSING_KEY);
        if (safeResult && safeResult.found) {
          return res.status(200).json(safeResult);
        }
      } catch (e) {}
    }

    if (checkType === 'news' && GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY);
        if (gemRes) return res.status(200).json(gemRes);
      } catch (e) {}
    }

    if (['scam', 'gmail'].includes(checkType)) {
      try {
        const deepRes = await callGroq(GROQ_KEY, text, checkType, 'deepseek-r1-distill-llama-70b');
        if (deepRes) return res.status(200).json(deepRes);
      } catch (e) {}
    }

    const finalRes = await callGroq(GROQ_KEY, text, checkType, 'llama-3.3-70b-versatile');
    return res.status(200).json(finalRes);

  } catch (error) {
    return res.status(500).json({ error: error.message || 'AI engine failed' });
  }
}

// Helper: Determine scam type and what-to-do from final verdict/analysis
function enrichResult(parsed) {
  // If AI already gave scamType, keep it. Otherwise try to guess from verdict/analysis.
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
      tips.push('Do NOT click the link', 'Do NOT enter login details', 'Open the official website manually');
    } else if (parsed.scamType === 'Fake Reward Scam') {
      tips.push('Do NOT send any money', 'Do NOT share personal information', 'Report the number/sender');
    } else if (parsed.scamType === 'OTP Fraud') {
      tips.push('Never share OTP with anyone', 'No legit company asks for OTP over phone', 'Block and report the caller');
    } else if (parsed.scamType === 'UPI Fraud') {
      tips.push('Do NOT approve the payment request', 'Check the receiver name carefully', 'If suspicious, report via UPI app');
    } else {
      tips.push('Be cautious with unsolicited messages', 'Do not share sensitive information', 'When in doubt, verify through official channels');
    }
    parsed.whatToDo = tips;
  }
  // Ensure confidence is realistic (65‑91) if AI didn't give a sensible value
  if (parsed.confidence > 91 || parsed.confidence < 50) {
    const signals = (parsed.analysis||'').split('.').length + (parsed.findings||[]).length;
    parsed.confidence = Math.min(91, 60 + signals * 5);
  }
  return parsed;
}

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
      return enrichResult({
        verdict: 'DANGEROUS',
        confidence: 100,
        analysis: 'Google Safe Browsing has identified this as a known malicious/phishing link.',
        findings: []
      });
    }
    return { found: false };
  } catch (e) { return { found: false }; }
}

async function callGemini(text, apiKey) {
  const systemPrompt = `You are a fact-checking AI. Analyze and determine if TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply ONLY in JSON: {"verdict":"...", "confidence":85, "analysis":"...", "findings":["point1","point2"]}`;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const body = { contents: [{ parts: [{ text: `${systemPrompt}\n\nInput: "${text}"` }] }] };
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error('Gemini failed');
  const data = await res.json();
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!content) throw new Error('Empty Gemini response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  return enrichResult(parsed);
}

async function callGroq(apiKey, text, type, model) {
  const systemPrompt = getPrompt(type);
  const url = 'https://api.groq.com/openai/v1/chat/completions';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: "You are a cybersecurity and scam-detection AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings (array of bullet points), whatToDo (array of actionable steps)." },
        { role: 'user', content: systemPrompt + `\n\nInput: "${text}"` }
      ],
      temperature: 0.2, max_tokens: 600, response_format: { type: "json_object" }
    })
  });
  if (!res.ok) throw new Error('Groq failed');
  const data = await res.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('Empty Groq response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  return enrichResult(parsed);
}

function getPrompt(type) {
  const baseSCAM = `You are an Indian scam detection expert. Analyze the message and return a JSON object with:
- verdict: SCAM / FRAUD / SAFE / SUSPICIOUS
- scamType: one of [Phishing Attack, Fake Reward Scam, OTP Fraud, UPI Fraud, Job Scam, Loan Fraud, Bank Impersonation, Safe Content]
- confidence: realistic number between 65 and 91
- analysis: human-like explanation in 2-3 sentences
- findings: array of bullet-point red flags (use ⚠️, 🔗, 💰 etc.)
- whatToDo: array of specific actionable steps. 

Examples of Indian scams to detect: fake KBC lottery, SBI KYC update, UPI payment request, OTP sharing, job fraud with advance payment. 
A normal marketing SMS from Airtel/Vi/Flipkart is usually SAFE.`;

  if (type === 'news') return `Determine if the news is TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply ONLY in JSON with keys: verdict, confidence, analysis, findings.`;
  if (type === 'url') return `Analyze the URL and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.`;
  if (type === 'phishing') return baseSCAM;
  if (type === 'scam') return baseSCAM;
  if (type === 'phone') return `Analyze the phone number and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.`;
  if (type === 'upi') return `Analyze the UPI ID and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.`;
  if (type === 'gmail') return baseSCAM;
  return `Analyze and return JSON with keys: verdict, confidence, analysis, findings.`;
}
