// api/verify.js - Debug version
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { text, checkType } = req.body;

  if (!text || !checkType) {
    return res.status(400).json({ error: 'Missing text or checkType' });
  }

  const GROQ_API_KEY = process.env.GROQ_API_KEY;
  const GROQ_MODEL = 'llama-3.3-70b-versatile';
  const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

  if (!GROQ_API_KEY) {
    return res.status(500).json({ error: 'GROQ_API_KEY not set' });
  }

  let systemPrompt = '';

  switch (checkType) {
    case 'news':
      systemPrompt = `You are a fact-checking AI. Determine if news is TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply ONLY in JSON: {"verdict":"...", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    case 'url':
      systemPrompt = `You are a cybersecurity AI. Analyze URL. Reply ONLY in JSON: {"verdict":"SAFE/DANGEROUS/PHISHING/SUSPICIOUS", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    case 'phishing':
      systemPrompt = `You are an anti-phishing AI. Analyze email/SMS. Reply ONLY in JSON: {"verdict":"PHISHING/SAFE/SUSPICIOUS", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    case 'scam':
      systemPrompt = `You are a scam detection AI. Analyze message. Reply ONLY in JSON: {"verdict":"SCAM/FRAUD/SAFE", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    case 'phone':
      systemPrompt = `You are a phone fraud detector. Analyze number. Reply ONLY in JSON: {"verdict":"SPAM/FRAUD/SAFE", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    case 'upi':
      systemPrompt = `You are a UPI fraud detector. Analyze UPI ID. Reply ONLY in JSON: {"verdict":"FRAUD/SUSPICIOUS/SAFE", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    case 'gmail':
      systemPrompt = `You are a Gmail fraud detector. Analyze email. Reply ONLY in JSON: {"verdict":"FRAUD/PHISHING/SCAM/SAFE", "confidence":85, "analysis":"...", "findings":"..."}`;
      break;
    default:
      return res.status(400).json({ error: 'Invalid checkType' });
  }

  try {
    const response = await fetch(GROQ_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: `Check: ${text}` }
        ],
        temperature: 0.3,
        max_tokens: 500,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Groq API error:', response.status, errorText);
      return res.status(500).json({ error: 'Groq API error ' + response.status });
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (!content) {
      return res.status(500).json({ error: 'AI empty response' });
    }

    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch (e) {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]);
      } else {
        return res.status(500).json({ error: 'Failed to parse AI response. Raw output: ' + content });
      }
    }

    if (!parsed.verdict || parsed.confidence === undefined || !parsed.analysis || !parsed.findings) {
      return res.status(500).json({ error: 'Incomplete AI response. Received: ' + JSON.stringify(parsed) });
    }

    return res.status(200).json(parsed);

  } catch (error) {
    console.error('Handler error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
