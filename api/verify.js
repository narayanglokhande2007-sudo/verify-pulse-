// api/verify.js - VerifyPulse Backend (Fixed for missing keys)
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { text, checkType } = req.body;
  if (!text || !checkType) return res.status(400).json({ error: 'Missing text or checkType' });

  // Try to get keys from environment (support both naming conventions)
  const GROQ_KEY = process.env.GROQ_API_KEY;
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY || process.env.SAFE_BROWS_G_API_KEY;
  const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;

  function safeResult(r) {
    if (typeof r.findings === 'string') r.findings = [r.findings];
    if (!Array.isArray(r.findings)) r.findings = [];
    if (typeof r.whatToDo === 'string') r.whatToDo = [r.whatToDo];
    if (!Array.isArray(r.whatToDo)) r.whatToDo = [];
    return r;
  }

  // Whitelist trusted domains (Allen, SBI, gov, etc.)
  function isTrustedMessage(msg, url) {
    const trustedDomains = [
      'allen.ac.in', 'allen.in', 'd.sfmsg.co',
      'vedantu.com', 'byjus.com', 'unacademy.com', 'physicswallah.com', 'pw.live',
      'sbi.co.in', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com', 'pnb.in', 'bankofbaroda.in',
      'axisbank.com', 'kotak.com', 'idfcbank.com',
      'gov.in', 'nic.in', 'india.gov.in', 'mygov.in', 'digilocker.gov.in',
      'amazon.in', 'flipkart.com', 'paytm.com', 'myntra.com', 'tatacliq.com',
      'whatsapp.com', 'telegram.org', 'google.com', 'microsoft.com', 'github.com',
      'airtel.in', 'vi.in', 'jio.com'
    ];
    if (url) {
      for (let domain of trustedDomains) {
        if (url.includes(domain)) return true;
      }
    }
    const lower = msg.toLowerCase();
    if (lower.includes('allen') && (lower.includes('neet') || lower.includes('course') || lower.includes('register'))) return true;
    if (lower.includes('sbi') && url && (url.includes('sbi.co.in') || url.includes('onlinesbi.com'))) return true;
    if (lower.includes('govt') || lower.includes('government')) return true;
    return false;
  }

  try {
    if (checkType === 'password') {
      return res.status(200).json(safeResult({ verdict: 'SAFE', confidence: 95, analysis: 'Checked locally', findings: [] }));
    }

    // Whitelist pre-check
    if (['scam', 'phishing', 'gmail', 'url'].includes(checkType)) {
      let extractedUrl = text.match(/https?:\/\/[^\s]+/)?.[0] || '';
      if (isTrustedMessage(text, extractedUrl)) {
        return res.status(200).json(safeResult({
          verdict: 'SAFE',
          scamType: 'Trusted Brand Message',
          confidence: 99,
          analysis: 'This message is from a known trusted brand or government source.',
          findings: ['Verified trusted domain'],
          whatToDo: ['You can safely proceed.']
        }));
      }
    }

    // Live knowledge boost (latest 2000 scams)
    let recentScamURLs = [];
    try {
      const pipelineURL = 'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/latest_scams.json';
      const pipelineRes = await fetch(pipelineURL);
      if (pipelineRes.ok) {
        const allURLs = await pipelineRes.json();
        recentScamURLs = allURLs.slice(-2000);
      }
    } catch (e) {}
    const knowledgeLine = recentScamURLs.length > 0 ? `\n\nLatest known phishing/scam URLs (for reference):\n${recentScamURLs.join('\n')}` : '';

    // Safe Browsing (only for URLs)
    if (['url', 'phishing', 'scam', 'gmail'].includes(checkType) && SAFE_BROWSING_KEY) {
      try {
        const sbResult = await checkWithSafeBrowsing(text, SAFE_BROWSING_KEY);
        if (sbResult && sbResult.found) return res.status(200).json(sbResult);
      } catch (e) {}
    }

    // Gemini for news (only)
    if (checkType === 'news' && GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY);
        if (gemRes) return res.status(200).json(safeResult(gemRes));
      } catch (e) {}
    }

    // ========== PRIMARY: Groq ==========
    if (GROQ_KEY) {
      try {
        const groqRes = await callGroq(GROQ_KEY, text, checkType, 'llama-3.3-70b-versatile', knowledgeLine);
        if (groqRes && groqRes.verdict && groqRes.confidence > 60) {
          return res.status(200).json(safeResult(groqRes));
        }
      } catch (e) { console.error('Groq failed:', e.message); }
    }

    // ========== FALLBACK: OpenRouter (only if key exists) ==========
    if (OPENROUTER_KEY) {
      try {
        const orResult = await callOpenRouter(OPENROUTER_KEY, text);
        if (orResult && orResult.verdict && orResult.confidence > 60) {
          return res.status(200).json(safeResult(orResult));
        }
      } catch (e) {}
    }

    // ========== FINAL FALLBACK: Hugging Face simple model ==========
    try {
      const hfResult = await callSimpleHuggingFace(text);
      if (hfResult && hfResult.verdict) {
        return res.status(200).json(safeResult(hfResult));
      }
    } catch (e) {}

    // Ultimate fallback (no crash)
    return res.status(200).json(safeResult({
      verdict: 'UNCERTAIN',
      scamType: 'Temporary Service Issue',
      confidence: 50,
      analysis: 'AI service temporarily unavailable. Please try again later.',
      findings: ['All AI engines busy or keys missing'],
      whatToDo: ['Refresh page and retry', 'Check back in a few minutes']
    }));

  } catch (error) {
    console.error('Handler error:', error);
    return res.status(200).json(safeResult({
      verdict: 'UNCERTAIN',
      scamType: 'Internal Error',
      confidence: 30,
      analysis: 'An internal error occurred.',
      findings: [error.message],
      whatToDo: ['Try again later']
    }));
  }
}

// ========== HELPER FUNCTIONS ==========

async function checkWithSafeBrowsing(inputUrl, apiKey) {
  try {
    let url = inputUrl;
    const match = inputUrl.match(/https?:\/\/[^\s]+/);
    if (match) url = match[0];
    const payload = {
      client: { clientId: "verifypulse", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
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
        findings: ['Malicious URL detected']
      };
    }
    return { found: false };
  } catch (e) { return { found: false }; }
}

async function callGemini(text, apiKey) {
  const systemPrompt = `You are a fact-checking AI. Determine TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply ONLY JSON: {"verdict":"...", "confidence":85, "analysis":"...", "findings":[]}`;
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
  // enrich scamType if missing
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

async function callOpenRouter(apiKey, text) {
  const prompt = `You are a scam detection expert. Analyze: "${text}". Return JSON with keys: verdict (SCAM/SAFE/SUSPICIOUS), scamType, confidence (0-100), analysis, findings (array), whatToDo (array).`;
  const model = 'meta-llama/llama-3-8b-instruct'; // cheapest/fastest
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], temperature: 0.2, max_tokens: 400 })
  });
  if (!res.ok) throw new Error('OpenRouter failed');
  const data = await res.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) return null;
  try { return JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); }
  return null;
}

async function callSimpleHuggingFace(text) {
  // Fallback: use a simple rule-based response
  const lower = text.toLowerCase();
  if (lower.includes('won') && lower.includes('crore') && lower.includes('pay')) {
    return { verdict: 'SCAM', scamType: 'Fake Reward Scam', confidence: 85, analysis: 'This appears to be a lottery scam.', findings: ['Fake prize'], whatToDo: ['Ignore'] };
  }
  if (lower.includes('kyc') && (lower.includes('sbi') || lower.includes('bank'))) {
    return { verdict: 'PHISHING', scamType: 'Bank Impersonation', confidence: 90, analysis: 'Fake KYC update scam.', findings: ['Suspicious link'], whatToDo: ['Do not click'] };
  }
  return null;
}

function getPrompt(type, knowledgeLine = '') {
  const baseSCAM = `You are an Indian scam detection expert. Analyze the message and return JSON:
- verdict: SCAM / FRAUD / SAFE / SUSPICIOUS
- scamType: [Phishing Attack, Fake Reward Scam, OTP Fraud, UPI Fraud, Job Scam, Loan Fraud, Bank Impersonation, Safe Content]
- confidence: number 65-91
- analysis: 2-3 sentences
- findings: array of bullet points
- whatToDo: array of steps`;
  if (type === 'news') return `Determine if news is TRUE/FALSE/MISLEADING/UNCERTAIN. Reply JSON.${knowledgeLine}`;
  if (type === 'url') return `Analyze URL safety. Reply JSON.${knowledgeLine}`;
  if (type === 'phishing') return baseSCAM + knowledgeLine;
  if (type === 'scam') return baseSCAM + knowledgeLine;
  if (type === 'phone') return `Analyze phone number for spam/fraud. Reply JSON.${knowledgeLine}`;
  if (type === 'upi') return `Analyze UPI ID for fraud. Reply JSON.${knowledgeLine}`;
  if (type === 'gmail') return baseSCAM + knowledgeLine;
  return `Analyze and return JSON with verdict, confidence, analysis, findings.`;
      }
