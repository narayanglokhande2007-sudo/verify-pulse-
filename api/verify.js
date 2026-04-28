export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { text, checkType, language = 'en' } = req.body;

  if (!text) {
    return res.status(400).json({ error: 'Text is required' });
  }

  const groqApiKey = process.env.GROQ_API_KEY;
  if (!groqApiKey) {
    return res.status(500).json({ error: 'GROQ_API_KEY not set' });
  }

  // Map checkType to a readable name
  const typeMap = {
    news: 'news/fact check',
    url: 'URL safety',
    phishing: 'phishing attempt',
    password: 'password strength',
    scam: 'scam message'
  };
  const checkTypeName = typeMap[checkType] || checkType;

  const prompt = `You are a cybersecurity scam detector. Analyze the following ${checkTypeName} and respond in ${language === 'hi' ? 'Hindi' : 'English'} language.

Return ONLY valid JSON in this exact format:
{
  "verdict": "SAFE / DANGEROUS / SCAM / TRUE / FALSE / UNCERTAIN / WEAK / STRONG",
  "confidence": 0-100,
  "type": "e.g., Phishing Attack, Fake News, Weak Password, etc.",
  "riskLevel": "High / Medium / Low",
  "whyScam": ["bullet point 1", "bullet point 2", ...] (at least 3 points),
  "whatToDo": ["advice 1", "advice 2", ...] (at least 3 points),
  "analysis": "short summary",
  "findings": "key red flags"
}

User input: ${text}`;

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${groqApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        response_format: { type: 'json_object' }
      })
    });

    const data = await response.json();
    let aiResult = JSON.parse(data.choices[0].message.content);

    // Ensure all fields exist
    const result = {
      verdict: aiResult.verdict || 'UNCERTAIN',
      confidence: aiResult.confidence || 50,
      type: aiResult.type || 'General Threat',
      riskLevel: aiResult.riskLevel || 'Medium',
      whyScam: Array.isArray(aiResult.whyScam) ? aiResult.whyScam : ['Suspicious content detected'],
      whatToDo: Array.isArray(aiResult.whatToDo) ? aiResult.whatToDo : ['Be cautious', 'Do not share personal info'],
      analysis: aiResult.analysis || 'Analysis not available',
      findings: aiResult.findings || 'No specific findings'
    };

    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: 'AI service error', details: error.message });
  }
}
