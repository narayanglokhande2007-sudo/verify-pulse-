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
        model: 'llama3-8b-8192',
        max_tokens: 500,
        messages: [
          {
            role: 'user',
            content: `Fact-check this text: "${text}"
            
Reply ONLY in this JSON format (no other text, no markdown):
{
  "verdict": "TRUE or FALSE or UNCERTAIN",
  "confidence": 85,
  "analysis": "2-3 line explanation",
  "findings": "Key points found"
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
