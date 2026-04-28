export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { text, checkType, language = 'en' } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'API key missing' });

  const prompt = `You are a security analyst. Check this ${checkType}: "${text}". Respond in ${language} in JSON: {"verdict": "SAFE/DANGEROUS/SCAM/TRUE/FALSE/UNCERTAIN", "confidence": 0-100, "analysis": "explanation", "findings": "red flags"}`;

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: [{ role: 'user', content: prompt }], temperature: 0.3 })
  });
  const data = await response.json();
  let result = JSON.parse(data.choices[0].message.content);
  res.status(200).json(result);
}
