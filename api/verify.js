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
    systemPrompt = `You are an expert fact-checker and investigative journalist. Today is April 28, 2026. 

CRITICAL RULES:
- For events after mid-2024, ALWAYS say UNCERTAIN - your knowledge may be outdated
- Never confirm someone is alive without 100% certainty
- Check for: false statistics, misleading headlines, out-of-context information
- Identify the source credibility if mentioned
- Look for emotional manipulation tactics`;

    userPrompt = `Fact-check this claim thoroughly: "${text}"

Analyze for:
1. Factual accuracy
2. Misleading context
3. Emotional manipulation
4. Source credibility
5. Recent event uncertainty

Reply ONLY in this JSON format:
{
  "verdict": "TRUE or FALSE or UNCERTAIN or MISLEADING",
  "confidence": 85,
  "analysis": "Detailed 3-4 line analysis with specific reasons",
  "findings": "List specific red flags or trust signals found"
}`;

  } else if (checkType === 'url') {
    systemPrompt = `You are an elite cybersecurity expert specializing in URL analysis and threat detection. You have deep knowledge of:
- Phishing domains and typosquatting
- Malicious URL patterns
- Fake website indicators
- Brand impersonation tactics
- Suspicious TLD patterns
- URL shortener abuse`;

    userPrompt = `Perform deep security analysis on this URL: "${text}"

Check for ALL of these red flags:
1. Domain age and reputation indicators
2. Typosquatting (e.g., paypa1.com instead of paypal.com)
3. Suspicious subdomains (e.g., paypal.login.evil.com)
4. Dangerous TLDs (.xyz, .tk, .ml used for scams)
5. HTTP vs HTTPS
6. URL structure anomalies
7. Brand impersonation
8. Fake government/bank sites
9. Free hosting abuse (000webhostapp, blogspot misuse)
10. Excessive redirects indicators

Reply ONLY in this JSON format:
{
  "verdict": "SAFE or SUSPICIOUS or DANGEROUS or PHISHING",
  "confidence": 90,
  "analysis": "Detailed security analysis explaining exactly why this URL is safe or dangerous",
  "findings": "Specific red flags found: list each issue separately"
}`;

  } else if (checkType === 'phishing') {
    systemPrompt = `You are a world-class cybersecurity expert specializing in social engineering and phishing detection. You can identify:
- Bank/Government impersonation
- Fake OTP requests
- Urgent action manipulation
- Prize/lottery scams
- KYC fraud messages
- Identity theft attempts
- Official-looking fake messages
- SMS spoofing patterns
- Email header manipulation indicators`;

    userPrompt = `Perform advanced phishing analysis on this message: "${text}"

Deep analyze for:
1. Sender impersonation (fake SBI, HDFC, RBI, Government, Amazon, etc.)
2. Urgency and fear tactics ("Your account will be blocked", "Act now")
3. Suspicious links or requests for personal info
4. Grammar and language inconsistencies
5. Fake official language patterns
6. OTP/PIN/Password request attempts
7. KYC fraud patterns
8. Prize/reward manipulation
9. Threat-based coercion
10. Official logo/format impersonation indicators

IMPORTANT: Even if message looks officially formatted, analyze carefully for fraud indicators.

Reply ONLY in this JSON format:
{
  "verdict": "SAFE or SUSPICIOUS or PHISHING or FRAUD",
  "confidence": 90,
  "analysis": "Detailed analysis: explain exactly which elements indicate fraud or legitimacy",
  "findings": "Specific fraud indicators found: list each red flag with explanation"
}`;

  } else if (checkType === 'scam') {
    systemPrompt = `You are an elite fraud detection expert with deep knowledge of:
- Investment scams and Ponzi schemes
- Job offer fraud
- Romance scams
- Lottery and prize fraud
- Advance fee fraud (419 scams)
- Crypto scams
- Work from home fraud
- Fake charity scams
- Technical support scams
- Insurance fraud patterns
- Real estate fraud
- Government impersonation scams`;

    userPrompt = `Perform comprehensive scam analysis on this content: "${text}"

Analyze for ALL scam patterns:
1. Too-good-to-be-true offers (high returns, easy money)
2. Advance payment requirements
3. Urgency and limited time pressure
4. Requests for personal/financial information
5. Unverifiable claims and promises
6. Fake testimonials indicators
7. Cryptocurrency payment requests
8. Gift card payment requests (major red flag)
9. Impersonation of authorities or companies
10. Emotional manipulation tactics
11. Fake job offers with upfront fees
12. Investment scheme patterns (MLM, Ponzi)

CRITICAL: Even if message appears professional and official, look for subtle scam patterns.

Reply ONLY in this JSON format:
{
  "verdict": "SAFE or SUSPICIOUS or SCAM or FRAUD",
  "confidence": 90,
  "analysis": "Comprehensive analysis: explain exactly why this is or isn't a scam with specific evidence",
  "findings": "All scam indicators found: list each red flag with detailed explanation"
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
        max_tokens: 800,
        temperature: 0.1,
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
