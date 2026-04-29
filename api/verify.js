// api/verify.js - Vercel Serverless Function
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { text, checkType } = req.body;

  if (!text || !checkType) {
    return res.status(400).json({ error: 'Missing text or checkType' });
  }

  // Groq API configuration
  const GROQ_API_KEY = process.env.GROQ_API_KEY;
  const GROQ_MODEL = 'llama-3.3-70b-versatile';
  const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

  if (!GROQ_API_KEY) {
    return res.status(500).json({ error: 'GROQ_API_KEY not set in environment' });
  }

  // Prompts for each check type
  let systemPrompt = '';
  let userPrompt = text;

  switch (checkType) {
    case 'news':
      systemPrompt = `You are a fact-checking AI. Analyze the given news/claim and determine if it is TRUE, FALSE, MISLEADING, or UNCERTAIN. Provide a confidence score (0-100), a detailed analysis, and specific key findings. Respond ONLY in JSON format:
{
  "verdict": "TRUE/FALSE/MISLEADING/UNCERTAIN",
  "confidence": 85,
  "analysis": "Explanation...",
  "findings": "Key points..."
}`;
      break;

    case 'url':
      systemPrompt = `You are a cybersecurity AI. Analyze the given URL and determine if it is SAFE, DANGEROUS, PHISHING, or SUSPICIOUS. Provide confidence (0-100), analysis, and key findings. Respond ONLY in JSON format as above.`;
      break;

    case 'phishing':
      systemPrompt = `You are an anti-phishing AI. Analyze the given email/SMS content and determine if it is PHISHING, SAFE, or SUSPICIOUS. Provide confidence, analysis, and key red flags. Respond ONLY in JSON.`;
      break;

    case 'scam':
      systemPrompt = `You are a scam detection AI. Analyze the given message/offer and determine if it is SCAM, FRAUD, or SAFE. Provide confidence, analysis, and findings. Respond ONLY in JSON.`;
      break;

    case 'phone':
      systemPrompt = `You are a phone fraud detector. Analyze the given phone number and determine if it is SPAM, FRAUD, or SAFE. Consider known scam patterns, country codes, etc. Provide confidence (0-100), analysis, and findings. Respond ONLY in JSON.`;
      break;

    case 'upi':
      systemPrompt = `You are a UPI fraud detector. Analyze the given UPI ID and determine if it is FRAUD, SUSPICIOUS, or SAFE. Consider common UPI scam patterns (e.g., fake apps, unknown IDs). Provide confidence, analysis, and findings. Respond ONLY in JSON.`;
      break;

    case 'gmail':
      systemPrompt = `You are a Gmail fraud detector. Analyze the given email content and determine if it is FRAUD, PHISHING, SCAM, or SAFE. Look for urgent language, fake links, attachments, sender spoofing etc. Provide confidence, analysis, and findings. Respond ONLY in JSON.`;
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
          { role: 'user', content: `Check this: "${userPrompt}"` }
        ],
        temperature: 0.3,
        max_tokens: 500,
        response_format: { type: "json_object" },  // Ensure JSON response
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      console.error('Groq API error:', error);
      return res.status(500).json({ error: 'AI service error' });
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (!content) {
      throw new Error('Empty response from AI');
    }

    // Parse the JSON from AI
    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch (err) {
      // Fallback: try to extract JSON from text
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('Invalid JSON from AI');
      }
    }

    // Validate required fields
    if (!parsed.verdict || parsed.confidence === undefined || !parsed.analysis || !parsed.findings) {
      throw new Error('Incomplete AI response');
    }

    return res.status(200).json({
      verdict: parsed.verdict,
      confidence: parsed.confidence,
      analysis: parsed.analysis,
      findings: parsed.findings,
    });
  } catch (error) {
    console.error('Handler error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
