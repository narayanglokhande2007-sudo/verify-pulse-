export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'verifypulse_webhook_2024';
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const MY_NUMBER = '+919373568817'; // अपना नंबर डालो

  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(200).send('WhatsApp route alive');
  }

  if (req.method === 'POST') {
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const message = body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0];

      if (!message || message.from === MY_NUMBER) {
        return res.status(200).send('ok');
      }

      const from = message.from;
      let userText = message.type === 'text' ? message.text?.body : `[${message.type}]`;

      if (!userText) return res.status(200).send('ok');

      // Debug: पहला जवाब
      await sendWhatsAppMessage(from, '⏳ Scanning... Please wait.');

      let result;
      try {
        result = await scanText(userText);
      } catch (scanError) {
        // अगर scanText में ही एरर आ गई
        await sendWhatsAppMessage(from, '❌ Scan Error: ' + scanError.message);
        return res.status(200).send('ok');
      }

      // Debug: अगर result खाली है
      if (!result) {
        await sendWhatsAppMessage(from, '❌ Scan result is empty');
        return res.status(200).send('ok');
      }

      // Format करके भेजो
      const reply = formatResult(result);
      await sendWhatsAppMessage(from, reply);

      return res.status(200).send('ok');
    } catch (error) {
      console.error('Outer error:', error);
      return res.status(200).send('ok');
    }
  }

  return res.status(405).send('Method not allowed');
}

// --- वही helper functions (कोई बदलाव नहीं) ---

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
  if (input.startsWith('http')) checkType = 'url';
  else if (/^[\d\s\-+()]{10,15}$/.test(input.replace(/[\s\-()]/g, ''))) checkType = 'phone';
  else if (input.includes('@')) {
    if (/@(okhdfc|oksbi|okicici|okaxis|paytm|upi)/i.test(input)) checkType = 'upi';
    else if (/(verify|login|password|account|subject:|dear)/i.test(input)) checkType = 'phishing';
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const systemPrompt = getScanPrompt(checkType);

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
  if (!content) throw new Error('Empty AI response');

  try {
    return JSON.parse(content);
  } catch {
    const match = content.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
    throw new Error('Invalid JSON from AI');
  }
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
