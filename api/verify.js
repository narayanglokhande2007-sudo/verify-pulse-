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

  const { text } = req.body;

  if (!text) {
    return res.status(400).json({ error: 'Text is required' });
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
          {
            role: 'system',
            content: `You are a fact-checking expert. Today is April 27, 2026. Your training data has a cutoff and you may not know about very recent events. 

IMPORTANT RULES:
- For recent events (after mid-2024), always say UNCERTAIN
- Never confidently say someone is alive if you are not 100% sure
- Always mention if your information might be outdated
- Be honest about your limitations`
          },
          {
            role: 'user',
            content: `Fact-check this claim: "${text}"

Reply ONLY in this JSON format (no other text):
{
  "verdict": "TRUE or FALSE or UNCERTAIN",
  "confidence": 50,
  "analysis": "Your analysis here. Mention if information might be outdated.",
  "findings": "Key findings here"
}`
          }
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
