module.exports = async (req, res) => {
  // === CORS HEADERS (Dusri websites ko allow karne ke liye) ===
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*'); 
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Pre-flight request handle karna
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Sirf POST request allow karna
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed', message: 'Only POST requests are accepted.' });
  }

  try {
    const { url } = req.body;

    // Check karna ki URL bheji gayi hai ya nahi
    if (!url) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'URL is required in the request body.'
      });
    }

    const targetUrl = url.toLowerCase();

    // -------------------------------------------------------------
    // MOCK AI LOGIC (Initial Testing ke liye)
    // Future me ise hata kar hum yahan Google Gemini API lagayenge
    // -------------------------------------------------------------
    const scamKeywords = ['scam', 'free-money', 'lottery', 'fake'];
    
    // Check karna kya URL me scam keywords hain
    const isScam = scamKeywords.some(keyword => targetUrl.includes(keyword));

    if (isScam) {
      return res.status(200).json({
        status: 'SCAM',
        threat_level: 'HIGH',
        message: 'Malicious activity detected by VerifyPulse.'
      });
    } else {
      return res.status(200).json({
        status: 'SAFE',
        threat_level: 'LOW',
        message: 'URL appears secure.'
      });
    }

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Something went wrong while processing the request.'
    });
  }
};
