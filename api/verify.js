export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { text, checkType } = req.body;
  if (!text || !checkType) return res.status(400).json({ error: 'Missing text or checkType' });

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY;

  try {
    // Password local hai, back-end pe nahi aata par safety ke liye handle kiya hai
    if (checkType === 'password') {
      return res.status(200).json({ verdict: 'SAFE', confidence: 100, analysis: 'Checked locally', findings: '' });
    }

    // URL, Phishing, Scam, Gmail – Safe Browsing se check (instant database)
    if (['url', 'phishing', 'scam', 'gmail'].includes(checkType) && SAFE_BROWSING_KEY) {
      try {
        const safeResult = await checkWithSafeBrowsing(text, SAFE_BROWSING_KEY);
        if (safeResult && safeResult.found) {
          return res.status(200).json(safeResult);
        }
      } catch (e) { /* fallback to next AI */ }
    }

    // Fake News – Gemini primary
    if (checkType === 'news' && GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY, 'news');
        if (gemRes) return res.status(200).json(gemRes);
      } catch (e) { /* fallback to Groq */ }
    }

    // Scam, Gmail – DeepSeek R1 (smarter reasoning)
    if (['scam', 'gmail'].includes(checkType)) {
      try {
        const deepRes = await callGroq(GROQ_KEY, text, checkType, 'deepseek-r1-distill-llama-70b');
        if (deepRes) return res.status(200).json(deepRes);
      } catch (e) { /* fallback to Llama 3 */ }
    }

    // Fallback – Groq Llama 3.3
    const finalRes = await callGroq(GROQ_KEY, text, checkType, 'llama-3.3-70b-versatile');
    return res.status(200).json(finalRes);

  } catch (error) {
    console.error('Final Error:', error);
    return res.status(500).json({ error: error.message || 'AI engine failed' });
  }
}

// ========== Safe Browsing Check ==========
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
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (!resp.ok) throw new Error('Safe Browsing API failed');
    const data = await resp.json();
    if (data.matches) {
      return {
        verdict: 'DANGEROUS',
        confidence: 100,
        analysis: 'Google Safe Browsing has identified this as a known malicious or phishing link.',
        findings: 'This URL is a known threat. Do not visit it.'
      };
    }
    return { found: false };
  } catch (e) {
    console.error('Safe Browsing Error:', e);
    return { found: false };
  }
}

// ========== Gemini Call ==========
async function callGemini(text, apiKey, type) {
  const systemPrompt = `You are a highly accurate fact-checking AI with access to the latest information. Analyze the given text and determine if it is TRUE, FALSE, MISLEADING, or UNCERTAIN. Provide a confidence score (0-100) and detailed reasoning in JSON format: {"verdict":"...", "confidence":85, "analysis":"...", "findings":"..."}`;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const body = {
    contents: [{ parts: [{ text: `${systemPrompt}\n\nInput: "${text}"` }] }]
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error('Gemini API failed');
  const data = await res.json();
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!content) throw new Error('Empty Gemini response');

  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }

  // Fix confidence scale for Gemini
  if (parsed.confidence > 0 && parsed.confidence <= 1) {
    parsed.confidence = Math.round(parsed.confidence * 100);
  }

  return {
    verdict: parsed.verdict,
    confidence: parsed.confidence,
    analysis: parsed.analysis,
    findings: parsed.findings
  };
}

// ========== Groq Call ==========
async function callGroq(apiKey, text, type, model) {
  const systemPrompt = getPrompt(type);
  const url = 'https://api.groq.com/openai/v1/chat/completions';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
          { role: 'system', content: "You are a helpful cybersecurity and fact-checking AI. Always respond in valid JSON format with keys: verdict, confidence, analysis, findings." },
          { role: 'user', content: systemPrompt + `\n\nInput: "${text}"` }
      ],
      temperature: 0.1,
      max_tokens: 500,
      response_format: { type: "json_object" }
    })
  });
  if (!res.ok) throw new Error('Groq API failed');
  const data = await res.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('Empty Groq response');

  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }

  // Fix confidence scale for Groq
  if (parsed.confidence > 0 && parsed.confidence <= 1) {
    parsed.confidence = Math.round(parsed.confidence * 100);
  }

  return {
    verdict: parsed.verdict,
    confidence: parsed.confidence,
    analysis: parsed.analysis,
    findings: parsed.findings
  };
}

// ========== Prompts ==========
function getPrompt(type) {
  const base = `Analyze the input and respond ONLY in JSON format with the keys "verdict", "confidence", "analysis", and "findings". `;
  if (type === 'news') return base + 'Determine if the news is TRUE, FALSE, MISLEADING, or UNCERTAIN.';
  if (type === 'url') return base + 'Determine if the URL is SAFE, DANGEROUS, PHISHING, or SUSPICIOUS.';
  if (type === 'phishing') return base + 'Determine if the text is PHISHING, SAFE, or SUSPICIOUS.';
  if (type === 'scam') return base + 'Determine if the message is SCAM, FRAUD, or SAFE.';
  if (type === 'phone') return base + 'Determine if the phone number is SPAM, FRAUD, or SAFE.';
  if (type === 'upi') return base + 'Determine if the UPI ID is FRAUD, SUSPICIOUS, or SAFE.';
  if (type === 'gmail') return base + 'Determine if the email is FRAUD, PHISHING, SCAM, or SAFE.';
  return base;
      }
