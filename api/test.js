export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'verifypulse_webhook_2024';
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const MY_NUMBER = '+919373568817'; // apna WhatsApp number daalo

  // GET: Webhook verification
  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(200).send('WhatsApp route alive');
  }

  // POST: Incoming message
  if (req.method === 'POST') {
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const message = body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0];

      // Ignore messages from myself to avoid loop
      if (!message || message.from === MY_NUMBER) {
        return res.status(200).send('ok');
      }

      const from = message.from;
      let userText = '';
      if (message.type === 'text') {
        userText = message.text?.body || '';
      } else {
        userText = `[${message.type} received]`;
      }

      if (userText) {
        // If command-like /start, /help, /score, handle specially
        if (userText.startsWith('/start')) {
          await sendWhatsAppMessage(from, '👋 Welcome to VerifyPulse Bot on WhatsApp!\n\nSend me any suspicious message, link, or email. I will check if it is a scam.\n\nCommands:\n/help - Get help\n/score - Learn about safety score');
          return res.status(200).send('ok');
        }

        if (userText.startsWith('/help')) {
          await sendWhatsAppMessage(from, '🔍 VerifyPulse Bot Help\n\n• Send me any message or link to check if it is a scam\n• Use /score to learn about safety scores\n• Visit https://verify-pulse.vercel.app for all 8 tools\n\nStay safe! 🛡️');
          return res.status(200).send('ok');
        }

        if (userText.startsWith('/score')) {
          await sendWhatsAppMessage(from, '🛡️ Safety Score\n\nVisit our website to see your personalized safety score:\nhttps://verify-pulse.vercel.app');
          return res.status(200).send('ok');
        }

        // Otherwise, scan with AI
        await sendWhatsAppMessage(from, '⏳ Scanning... Please wait.');

        const scanResult = await scanText(userText);
        const reply = formatResult(scanResult);
        await sendWhatsAppMessage(from, reply);
      }

      return res.status(200).send('ok');
    } catch (error) {
      console.error('WhatsApp bot error:', error);
      return res.status(200).send('ok');
    }
  }

  return res.status(405).send('Method not allowed');
}

// --- Helper Functions ---

async function sendWhatsAppMessage(to, text) {
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
  await fetch(`https://graph.facebook.com/v25.0/${PHONE_NUMBER_ID}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${ACCESS_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to,
      type: 'text',
      text: { body: text }
    })
  });
}

async function scanText(input) {
  let checkType = 'scam';
  if (input.startsWith('http://') || input.startsWith('https://')) checkType = 'url';
  else if (/^[\d\s\-+()]{10,15}$/.test(input.replace(/[\s\-()]/g, ''))) checkType = 'phone';
  else if (input.includes('@')) {
    if (/@(okhdfc|oksbi|okicici|okaxis|paytm|upi)/i.test(input)) checkType = 'upi';
    else if (/(verify|login|password|account|subject:|dear)/i.test(input)) checkType = 'phishing';
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const systemPrompt = getScanPrompt(checkType);

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'You are a cybersecurity AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings, whatToDo.' },
          { role: 'user', content: systemPrompt + '\n\nInput: "' + input + '"' }
        ],
        temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
      })
    });

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    if (content) {
      try { return JSON.parse(content); } catch {
        const match = content.match(/\{[\s\S]*\}/);
        if (match) return JSON.parse(match[0]);
      }
    }
  } catch (e) {
    console.error('Scan error:', e);
  }

  return {
    verdict: 'UNCERTAIN',
    scamType: 'Unknown',
    confidence: 50,
    analysis: 'Unable to analyze right now. Try again shortly.',
    findings: ['Service interruption'],
    whatToDo: ['Try again later']
  };
}

function getScanPrompt(type) {
  if (type === 'url') return 'Determine if SAFE, DANGEROUS, PHISHING, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phishing') return 'Determine if PHISHING, SAFE, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phone') return 'Determine if SPAM, FRAUD, or SAFE. Reply ONLY in JSON.';
  if (type === 'upi') return 'Determine if FRAUD, SUSPICIOUS, or SAFE. Reply ONLY in JSON.';
  return 'You are an Indian scam detection expert. Determine if SCAM, FRAUD, or SAFE. Reply ONLY in JSON.';
}

function formatResult(result) {
  if (result.confidence > 0 && result.confidence <= 1) {
    result.confidence = Math.round(result.confidence * 100);
  }

  const verdict = (result.verdict || '').toUpperCase();
  const emoji = ['DANGEROUS','SCAM','FRAUD','PHISHING'].includes(verdict) ? '🔴' :
                ['SUSPICIOUS','MISLEADING'].includes(verdict) ? '⚠️' : '✅';
  const status = ['DANGEROUS','SCAM'].includes(verdict) ? 'Dangerous' :
                 ['SUSPICIOUS','MISLEADING'].includes(verdict) ? 'Suspicious' : 'Safe';

  let text = `${emoji} *${status}*\n📋 Type: ${result.scamType || 'N/A'}\n📊 Confidence: ${result.confidence || 'N/A'}%\n\n🔍 ${result.analysis || ''}`;

  (result.findings || []).forEach(f => text += `\n• ${f}`);
  (result.whatToDo || []).forEach(w => text += `\n🛡️ ${w}`);

  return text + '\n\n🌐 verify-pulse.vercel.app';
}
