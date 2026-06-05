module.exports = async (req, res) => {
  // === CORS HEADERS (Dusri websites ko allow karne ke liye) ===
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*'); 
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed', message: 'Only POST requests are accepted.' });
  }

  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'Bad Request', message: 'URL is required.' });
    }

    // -------------------------------------------------------------
    // CONNECTING TO THE MASTER 13-AI SYSTEM
    // B2B ki request ko chupchap VerifyPulse ke Master engine me bheja ja raha hai
    // Bina kisi purane code ko delete ya change kiye!
    // -------------------------------------------------------------
    
    // Website ka asli address pata karna (e.g., verify-pulse.vercel.app)
    const host = req.headers.host;
    const protocol = host.includes('localhost') ? 'http' : 'https';
    const masterEngineUrl = `${protocol}://${host}/api/verify`;

    // Master engine ko data usi format me bhejna jaise Website bhejti hai
    const response = await fetch(masterEngineUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        text: url,
        checkType: 'unified'
      })
    });

    if (!response.ok) {
      throw new Error('Master AI Engine failed to respond.');
    }

    // Master engine se aaya hua 13 AI models ka combined result
    const masterResult = await response.json();

    // B2B companiyon ko ekdam clean, professional aur detailed result dena
    return res.status(200).json({
      status: masterResult.verdict || 'UNCERTAIN',
      threat_level: (masterResult.verdict === 'DANGEROUS' || masterResult.verdict === 'SCAM' || masterResult.verdict === 'FRAUD') ? 'HIGH' : masterResult.verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
      scam_type: masterResult.scamType || 'Unknown',
      confidence: masterResult.confidence || 0,
      message: masterResult.analysis || 'Analysis complete.',
      action_steps: masterResult.whatToDo || []
    });

  } catch (error) {
    console.error('B2B API Error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to process request through the Master AI Engine.'
    });
  }
};
