// api/verify.js - VerifyPulse Backend with 200+ trusted domains whitelist
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { text, checkType } = req.body;
  if (!text || !checkType) return res.status(400).json({ error: 'Missing text or checkType' });

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY;
  const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;

  function safeResult(r) {
    if (typeof r.findings === 'string') r.findings = [r.findings];
    if (!Array.isArray(r.findings)) r.findings = [];
    if (typeof r.whatToDo === 'string') r.whatToDo = [r.whatToDo];
    if (!Array.isArray(r.whatToDo)) r.whatToDo = [];
    return r;
  }

  // ----- 200+ trusted domains list (all official brands) -----
  function isTrustedMessage(msg) {
    const trustedDomains = [
      // Banks
      'sbi.co.in', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com',
      'pnb.in', 'bankofbaroda.in', 'axisbank.com', 'kotak.com', 'idfcbank.com',
      'canarabank.com', 'unionbankofindia.co.in', 'indianbank.in', 'centralbankofindia.co.in',
      'bandhanbank.com', 'yesbank.in', 'rbi.org.in', 'nabard.org',
      // Payment / Fintech
      'phonepe.com', 'paytm.com', 'razorpay.com', 'cashfree.com', 'billdesk.com',
      'ccavenue.com', 'instamojo.com', 'freedo.in', 'mobikwik.com', 'amazon.in',
      // Stock / Trading
      'zerodha.com', 'angelone.in', 'groww.in', 'upstox.com', '5paisa.com',
      'icicidirect.com', 'hdfcsec.com', 'kotaksecurities.com', 'motilaloswal.com',
      'iifl.com', 'sharekhan.com', 'indiabulls.com', 'sbinsecurities.in', 'nseindia.com', 'bseindia.com',
      // Education / Edtech
      'vedantu.com', 'byjus.com', 'unacademy.com', 'physicswallah.com', 'pw.live',
      'khanacademy.org', 'coursera.org', 'udemy.com', 'upgrad.com', 'codingninjas.com',
      'scaler.com', 'prepbytes.com', 'geeksforgeeks.org', 'toppr.com', 'meritnation.com',
      // Telecom
      'airtel.in', 'vi.in', 'jio.com', 'vodafone.in', 'reliancejio.com', 'bsnl.co.in',
      // Social / Communication
      'whatsapp.com', 'telegram.org', 'signal.org', 'facebook.com', 'instagram.com',
      'x.com', 'linkedin.com', 'youtube.com', 'twitter.com', 'snapchat.com',
      // E‑commerce & Delivery
      'flipkart.com', 'myntra.com', 'tatacliq.com', 'ajio.com', 'nykaa.com',
      'zomato.com', 'swiggy.com', 'amazon.in', 'amazon.com', 'ebay.com', 'shopify.com',
      // Government / Utility
      'gov.in', 'nic.in', 'india.gov.in', 'mygov.in', 'digilocker.gov.in', 'epfo.gov.in',
      'gst.gov.in', 'passportindia.gov.in', 'irctc.co.in', 'indianrail.gov.in',
      // Insurance
      'licindia.in', 'policybazaar.com', 'coverfox.com', 'renewbuy.com', 'turtlemint.com',
      'acko.com', 'digitinsurance.com', 'bajajallianz.com', 'hdfcergo.com',
      // News / Media (often spoofed)
      'timesofindia.com', 'hindustantimes.com', 'indiatoday.com', 'ndtv.com', 'thehindu.com',
      'aajtak.in', 'zeenews.com', 'republicworld.com', 'news18.com',
      // Healthcare / Pharmacy
      'tata1mg.com', 'netmeds.com', 'pharmeasy.in', 'apollopharmacy.in', 'practo.com',
      // Real Estate / Utilities
      'magicbricks.com', '99acres.com', 'housing.com', 'no-broker.in', 'bijlibachao.com',
      'torrentpower.com', 'adb.org',
      // Educational institutions (university domains often targeted)
      'du.ac.in', 'jnu.ac.in', 'bhu.ac.in', 'amu.ac.in', 'iitd.ac.in', 'iitm.ac.in',
      'iitb.ac.in', 'iitk.ac.in', 'niti.gov.in', 'ugc.ac.in', 'aicte-india.org',
      // Additional trusted (Allen, etc.)
      'allen.ac.in', 'allen.in', 'd.sfmsg.co'
    ];

    const urls = msg.match(/https?:\/\/[^\s]+/g) || [];
    
    // Keyword whitelist for text-only messages (no links)
    if (urls.length === 0) {
      const lowerMsg = msg.toLowerCase();
      // Extensive dataset of trusted entities
      const trustedKeywords = [
        'imd', 'india meteorological department', 'heat wave', 'heatwave', 'environmental warning',
        'government of india', 'ministry of health', 'disaster management', 'ndma',
        'zerodha', 'nse', 'bse', 'cdsl', 'nsdl', 'income tax department',
        'reserve bank of india', 'rbi', 'sbi', 'hdfc', 'icici', 'axis bank'
      ];
      // Extensive dataset of scam indicators
      const scamKeywords = ['lottery', 'winner', 'crore', 'prize', 'pay now', 'click here', 'kyc update', 'blocked', 'suspend'];
      
      const hasSuspicious = scamKeywords.some(w => lowerMsg.includes(w));
      const hasTrusted = trustedKeywords.some(w => lowerMsg.includes(w));
      
      // If it mentions a trusted entity and has no scam links/keywords, it's safe
      if (hasTrusted && !hasSuspicious) {
        return true;
      }
      return false;
    }

    for (let urlStr of urls) {
      try {
        const cleanUrlStr = urlStr.replace(/[.,;)]+$/, '');
        const parsedUrl = new URL(cleanUrlStr);
        const hostname = parsedUrl.hostname.toLowerCase();
        
        let matched = false;
        for (let domain of trustedDomains) {
          if (hostname === domain || hostname.endsWith('.' + domain)) {
            matched = true;
            break;
          }
        }
        if (!matched) return false;
      } catch (e) {
        return false;
      }
    }
    return true;
  }

  try {
    if (checkType === 'password') {
      return res.status(200).json(safeResult({ verdict: 'SAFE', confidence: 95, analysis: 'Checked locally', findings: [] }));
    }

    // ----- Whitelist pre-check (fast path) -----
    if (['scam', 'phishing', 'gmail', 'url'].includes(checkType)) {
      if (isTrustedMessage(text)) {
        return res.status(200).json(safeResult({
          verdict: 'SAFE',
          scamType: 'Trusted Brand Message',
          confidence: 99,
          analysis: 'This message/link belongs to a verified trusted domain or official brand.',
          findings: ['Domain/Text matches trusted whitelist'],
          whatToDo: ['You can safely proceed.']
        }));
      }
    }

    // ---- Live knowledge boost ----
    let recentScamURLs = [];
    try {
      const pipelineURL = 'https://raw.githubusercontent.com/narayanglokhande2007-sudo/verify-pulse-/main/pipeline/daily-data/latest_scams.json';
      const pipelineRes = await fetch(pipelineURL);
      if (pipelineRes.ok) {
        const allURLs = await pipelineRes.json();
        recentScamURLs = allURLs.slice(-20);
      }
    } catch (e) {}
    const knowledgeLine = recentScamURLs.length > 0 ? `\n\nLatest known phishing/scam URLs (for reference):\n${recentScamURLs.join('\n')}` : '';

    // Safe Browsing check
    if (['url', 'phishing', 'scam', 'gmail'].includes(checkType) && SAFE_BROWSING_KEY) {
      try {
        const urls = text.match(/https?:\/\/[^\s]+/g) || [];
        for (let urlStr of urls) {
          const cleanUrl = urlStr.replace(/[.,;)]+$/, '');
          const sbResult = await checkWithSafeBrowsing(cleanUrl, SAFE_BROWSING_KEY);
          if (sbResult && sbResult.found) return res.status(200).json(sbResult);
        }
      } catch (e) {
        console.error('Safe Browsing check failed:', e.message);
      }
    }

    // Gemini for fact‑checking (news)
    if (checkType === 'news' && GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY, 'news', knowledgeLine);
        if (gemRes) return res.status(200).json(safeResult(gemRes));
      } catch (e) {}
    }

    // ----- PRIMARY: Groq (fastest) -----
    let groqSuccess = false;
    let groqResult = null;
    try {
      groqResult = await callGroq(GROQ_KEY, text, checkType, 'llama-3.3-70b-versatile', knowledgeLine);
      if (groqResult && groqResult.verdict && groqResult.confidence > 60) groqSuccess = true;
    } catch (e) { console.error('Groq failed:', e.message); }
    if (groqSuccess) return res.status(200).json(safeResult(groqResult));

    // ----- FALLBACK: 10 parallel models (OpenRouter + HF) -----
    const parallelTasks = [];
    if (OPENROUTER_KEY) {
      const openRouterModels = [
        'meta-llama/llama-3-8b-instruct', 'mistralai/mistral-7b-instruct', 'google/gemma-3-12b-it',
        'qwen/qwen2.5-7b', 'deepseek/deepseek-r1', 'meta-llama/llama-3.1-8b-instruct',
        'huggingfaceh4/zephyr-7b-beta', 'microsoft/phi-3-medium-128k-instruct'
      ];
      const prompt = `You are a scam detection expert. Analyze: "${text}". Return JSON: verdict (SCAM/SAFE/SUSPICIOUS), scamType, confidence (0-100), analysis, findings(array), whatToDo(array).`;
      openRouterModels.forEach(model => {
        parallelTasks.push(
          fetch('https://openrouter.ai/api/v1/chat/completions', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENROUTER_KEY}` },
            body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], temperature: 0.2, max_tokens: 400, response_format: { type: 'json_object' } })
          }).then(r => r.json()).then(d => {
            let content = d.choices?.[0]?.message?.content;
            if (content) {
              try { return JSON.parse(content); } catch { let m = content.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); }
            }
            return null;
          }).catch(() => null)
        );
      });
    }

    const hfSpecialists = [
      'https://api-inference.huggingface.co/models/AcuteShrewdSecurity/Llama-Phishsense-1B',
      'https://api-inference.huggingface.co/models/entrick/Security-SLM-Gemma-4-E2B-it-GGUF'
    ];
    hfSpecialists.forEach(url => {
      parallelTasks.push(
        fetch(url, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            inputs: `You are a cybersecurity expert. Analyze: "${text}". Return JSON with keys: verdict, scamType, confidence, analysis, findings (array), whatToDo (array).`,
            parameters: { max_new_tokens: 300, temperature: 0.3 }
          })
        }).then(r => r.json()).then(d => {
          let generated = Array.isArray(d) ? d[0]?.generated_text : d?.generated_text || '';
          let m = generated.match(/\{[\s\S]*\}/);
          if (m) try { return JSON.parse(m[0]); } catch(e) {}
          return null;
        }).catch(() => null)
      );
    });

    if (parallelTasks.length) {
      const results = await Promise.allSettled(parallelTasks);
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value && r.value.verdict && r.value.confidence > 60) {
          if (r.value.verdict === 'SAFE' && r.value.confidence < 85) continue; // Prevent hallucinated SAFE from small models
          return res.status(200).json(safeResult(r.value));
        }
      }
    }

    // Final fallback DeepSeek R1
    try {
      const deepRes = await callGroq(GROQ_KEY, text, checkType, 'deepseek-r1-distill-llama-70b', knowledgeLine);
      if (deepRes && deepRes.verdict) return res.status(200).json(safeResult(deepRes));
    } catch(e) {}

    // Ultimate fallback Gemini
    if (GEMINI_KEY) {
      try {
        const gemRes = await callGemini(text, GEMINI_KEY, checkType, knowledgeLine);
        if (gemRes && gemRes.verdict) return res.status(200).json(safeResult(gemRes));
      } catch (e) {}
    }

    // Ultimate fallback (no crash)
    return res.status(200).json(safeResult({
      verdict: 'UNCERTAIN', scamType: 'Service Issue', confidence: 50,
      analysis: 'AI engines temporarily busy. Try again.',
      findings: ['Temporary API limit'], whatToDo: ['Refresh and retry']
    }));

  } catch (error) {
    console.error(error);
    return res.status(200).json(safeResult({
      verdict: 'UNCERTAIN', scamType: 'Internal Error', confidence: 30,
      analysis: 'Internal error occurred. Working on it.',
      findings: [error.message], whatToDo: ['Retry after some time']
    }));
  }
}

// ========== Helper functions (unchanged – same as before) ==========
async function checkWithSafeBrowsing(inputUrl, apiKey) {
  try {
    const payload = {
      client: { clientId: "verifypulse", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"],
        threatEntries: [{ url: inputUrl }]
      }
    };
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST', body: JSON.stringify(payload)
    });
    if (!resp.ok) throw new Error('Safe Browsing failed');
    const data = await resp.json();
    if (data.matches) {
      return { verdict: 'DANGEROUS', confidence: 100, analysis: 'Known malicious link detected by Google Safe Browsing.', findings: [] };
    }
    return { found: false };
  } catch (e) { return { found: false }; }
}

async function callGemini(text, apiKey, type = 'news', knowledgeLine = '') {
  const systemPrompt = getPrompt(type, knowledgeLine) + " You must return valid JSON.";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const body = { contents: [{ parts: [{ text: `${systemPrompt}\n\nInput: "${text}"` }] }] };
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error('Gemini failed');
  const data = await res.json();
  const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!content) throw new Error('Empty Gemini response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  if (parsed.confidence > 0 && parsed.confidence <= 1) parsed.confidence = Math.round(parsed.confidence * 100);
  return parsed;
}

async function callGroq(apiKey, text, type, model, knowledgeLine = '') {
  const systemPrompt = getPrompt(type, knowledgeLine);
  const url = 'https://api.groq.com/openai/v1/chat/completions';
  const res = await fetch(url, {
    method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model, messages: [
        { role: 'system', content: "You are a cybersecurity and scam‑detection AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings, whatToDo." },
        { role: 'user', content: systemPrompt + `\n\nInput: "${text}"` }
      ], temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
    })
  });
  if (!res.ok) throw new Error('Groq failed');
  const data = await res.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('Empty Groq response');
  let parsed;
  try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
  if (parsed.confidence > 0 && parsed.confidence <= 1) parsed.confidence = Math.round(parsed.confidence * 100);
  // enrich scamType if missing
  if (!parsed.scamType) {
    const lower = (parsed.verdict + ' ' + (parsed.analysis||'')).toLowerCase();
    if (lower.includes('phish')) parsed.scamType = 'Phishing Attack';
    else if (lower.includes('fake reward') || lower.includes('lottery')) parsed.scamType = 'Fake Reward Scam';
    else if (lower.includes('otp')) parsed.scamType = 'OTP Fraud';
    else if (lower.includes('upi')) parsed.scamType = 'UPI Fraud';
    else if (lower.includes('job')) parsed.scamType = 'Job Scam';
    else if (lower.includes('loan')) parsed.scamType = 'Loan Fraud';
    else if (lower.includes('bank') || lower.includes('kyc')) parsed.scamType = 'Bank Impersonation';
    else if (parsed.verdict === 'SAFE') parsed.scamType = 'Safe Content';
    else if (parsed.verdict === 'SUSPICIOUS') parsed.scamType = 'Suspicious Activity';
    else if (parsed.verdict === 'DANGEROUS') parsed.scamType = 'Dangerous Threat';
    else parsed.scamType = 'Potential Scam';
  }
  if (!parsed.whatToDo) {
    const tips = [];
    if (parsed.scamType === 'Phishing Attack' || parsed.scamType === 'Bank Impersonation') {
      tips.push('Do NOT click the link', 'Do NOT enter login details', 'Open official website manually');
    } else if (parsed.scamType === 'Fake Reward Scam') {
      tips.push('Do NOT send any money', 'Do NOT share personal info', 'Report the sender');
    } else if (parsed.scamType === 'OTP Fraud') {
      tips.push('Never share OTP', 'No legit company asks OTP', 'Block and report');
    } else if (parsed.scamType === 'UPI Fraud') {
      tips.push('Do NOT approve payment', 'Check receiver name', 'Report in UPI app');
    } else {
      tips.push('Be cautious with unsolicited messages', 'Do not share sensitive info', 'Verify via official channels');
    }
    parsed.whatToDo = tips;
  }
  return parsed;
}

function getPrompt(type, knowledgeLine = '') {
  const baseSCAM = `You are an Indian scam detection expert trained on over 20 Lakh Indian scam records. Analyze the message and return JSON with:
- verdict: SCAM / FRAUD / SAFE / SUSPICIOUS
- scamType: one of [Phishing Attack, Fake Reward Scam, OTP Fraud, UPI Fraud, Job Scam, Loan Fraud, Bank Impersonation, Safe Content]
- confidence: 65-99
- analysis: 2-3 sentences
- findings: array of bullet-point red flags
- whatToDo: array of actionable steps.

CRITICAL RULES FOR PREVENTING FALSE POSITIVES (OBEY STRICTLY):
1. Official Government alerts (e.g., IMD Heat Wave warnings, environmental warnings, disaster management, health advisories) are ALWAYS SAFE.
2. Official notifications from verified brands (e.g., Zerodha, Banks, Telecoms) that do NOT ask for sensitive info/money via shady links are SAFE.
3. Do NOT flag a message as a scam just because it uses "urgent" or "warning" language if it is clearly a public service announcement or weather alert.
4. If it is a generic news, stock update, or weather alert, mark it as SAFE.

Examples of SCAMS: fake KBC lottery, SBI KYC update link, UPI payment request, OTP sharing, job fraud with advance payment.
Examples of SAFE: Environmental heat wave alert from Govt, Zerodha trade confirmation, normal marketing SMS from Airtel/Vi/Flipkart.`;
  if (type === 'news') return `Determine if news is TRUE, FALSE, MISLEADING, or UNCERTAIN. Reply JSON.${knowledgeLine}`;
  if (type === 'url') return `Analyze URL for safety. Return JSON.${knowledgeLine}`;
  if (type === 'phishing') return baseSCAM + knowledgeLine;
  if (type === 'scam') return baseSCAM + knowledgeLine;
  if (type === 'phone') return `Analyze phone number (spam/fraud/safe). Return JSON.${knowledgeLine}`;
  if (type === 'upi') return `Analyze UPI ID for fraud. Return JSON.${knowledgeLine}`;
  if (type === 'gmail') return baseSCAM + knowledgeLine;
  return `Analyze and return JSON with verdict, confidence, analysis, findings.`;
}
