export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  return res.status(200).json({
    verdict: 'SAFE',
    scamType: 'Test Response',
    confidence: 95,
    analysis: 'Backend is reachable. Now we will fix real API keys.',
    findings: ['Server working'],
    whatToDo: ['Next: renew Groq & Gemini API keys']
  });
}
