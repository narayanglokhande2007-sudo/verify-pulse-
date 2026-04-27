export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { text, checkType } = req.body;

  if (!text) {
    return res.status(400).json({ error: 'Text is required' });
  }

  let systemPrompt = '';
  let userPrompt = '';

  if (checkType === 'news') {
    systemPrompt = `You are a fact-checking expert. Today is April 27, 2026. Your training data has a cutoff and you may not know about very recent events.
IMPORTANT RULES:
- For recent events (after mid-2024), always say UNCERTAIN
- Never confidently say someone is alive if you are not 100% sure
- Always mention if your information might be outdated`;

    userPrompt = `Fact-check this claim: "${text}"
Reply ONLY in this JSON format:
{
  "verdict": "TRUE or FALSE or UNCERTAIN",
  "confidence": 50,
  "analysis": "Your analysis. Mention if info might be outdated.",
  "findings": "Key findings"
}`;

  } else if (checkType === 'url') {
    systemPrompt = `You are a cybersecurity expert specializing in URL and website safety analysis.`;
    userPrompt = `Analyze this URL for safety: "${text}"
Check for: phishing, malware, scam patterns, suspicious domains, fake websites.
Reply ONLY in this JSON format:
{
  "verdict": "SAFE or SUSPICIOUS or DANGEROUS",
  "confidence": 85,
  "analysis": "Why this URL is safe or dangerous",
  "findings": "Specific red flags or trust signals found"
}`;

  } else if (checkType === 'phishing') {
    systemPrompt = `You are a cybersecurity expert specializing in phishing and social engineering detection.`;
    userPrompt = `Analyze this message for phishing attempts: "${text}"
Check for: fake links, urgency tactics, impersonation, suspicious requests, grammar errors.
Reply ONLY in this JSON format:
{
  "verdict": "SAFE or SUSPICIOUS or PHISHING",
  "confidence": 85,
  "analysis": "Why this is or isn't phishing",
  "findings": "Specific phishing indicators found"
}`;

  } else if (checkType === 'scam') {
    systemPrompt = `You are a cybersecurity expert specializing in scam detection.`;
    userPrompt = `Analyze this for scam indicators: "${text}"
Check for: too good to be true offers, fake prizes, advance fee fraud, impersonation, urgency.
Reply ONLY in this JSON format:
{
  "verdict": "SAFE or SUSPICIOUS or SCAM",
  "confidence": 85,
  "analysis": "Why this is or isn't a scam",
  "findings": "Specific scam indicators found"
}`;
  }

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 500,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ]
      })
    });

    const data = await response.json();

    if (data.error) {
      return res.status(500).json({ error: data.error.message });
    }

    const resultText = data.choices[0].message.content;
    
    let result;
    try {
      result = JSON.parse(resultText);
    } catch (e) {
      const jsonMatch = resultText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        result = JSON.parse(jsonMatch[0]);
      } else {
        return res.status(500).json({ error: 'Invalid response from AI' });
      }
    }

    return res.status(200).json(result);

  } catch (error) {
    return res.status(500).json({ error: 'Server error: ' + error.message });
  }
}
