export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  // Fake response – no AI calls
  return res.status(200).json({
    verdict: 'SAFE',
    scamType: 'Test Response',
    confidence: 95,
    analysis: 'This is a test. Your website backend is reachable. AI APIs will be fixed next.',
    findings: ['Backend working'],
    whatToDo: ['Now we will fix the real API keys']
  });
}
