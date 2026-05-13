export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;

  // ============= VERIFICATION (GET request from Meta) =============
  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('Webhook verified');
      return res.status(200).send(challenge);
    }
    return res.status(403).send('Verification failed');
  }

  // ============= INCOMING MESSAGE (POST request) =============
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    console.log('Webhook received:', JSON.stringify(body).substring(0, 500));

    const entries = body?.entry;
    if (!entries) {
      return res.status(200).send('ok');
    }

    for (const entry of entries) {
      const changes = entry?.changes;
      if (!changes) continue;

      for (const change of changes) {
        const messages = change?.value?.messages;
        if (!messages) continue;

        for (const message of messages) {
          const from = message.from; // user's phone number
          let text = '';

          if (message.type === 'text') {
            text = message.text?.body || '';
          } else {
            text = `[${message.type} message received]`;
          }

          if (text) {
            // Scan using existing AI (same as website & Telegram)
            const result = await scanText(text);
            const reply = formatWhatsAppResult(result);

            // Send reply
            await sendWhatsAppMessage(from, reply);
          }
        }
      }
    }

    return res.status(200).send('ok');

  } catch (error) {
    console.error('WhatsApp bot error:', error);
    return res.status(200).send('ok'); // always respond 200 to Meta
  }
}

// ============= SEND WHATSAPP MESSAGE =============
async function sendWhatsAppMessage(to, text) {
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;

  const url = `https://graph.facebook.com/v25.0/${PHONE_NUMBER_ID}/messages`;

  await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${ACCESS_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to: to,
      type: 'text',
      text: { body: text }
    })
  });
}

// ============= SCAN INPUT (same as Telegram bot) =============
async function scanText(input) {
  let checkType = 'scam';
  if (input.startsWith('http://') || input.startsWith('https://')) {
    checkType = 'url';
  } else if (/^[\d\s\-+()]{10,15}$/.test(input.replace(/[\s\-()]/g, ''))) {
    checkType = 'phone';
  } else if (input.includes('@')) {
    if (/@(okhdfc|oksbi|okicici|okaxis|paytm|upi)/i.test(input)) {
      checkType = 'upi';
    } else if (/(verify|login|password|account|subject:|dear)/i.test(input)) {
      checkType = 'phishing';
    }
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const systemPrompt = getScanPrompt(checkType);

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'You are a cybersecurity and scam-detection AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings, whatToDo.' },
          { role: 'user', content: systemPrompt + '\n\nInput: "' + input + '"' }
        ],
        temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
      })
    });

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (content) {
      let parsed;
      try { parsed = JSON.parse(content); } catch {
        const match = content.match(/\{[\s\S]*\}/);
        if (match) parsed = JSON.parse(match[0]);
        else throw new Error('Invalid JSON');
      }
      return parsed;
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
    whatToDo: ['Send /start to try again']
  };
}

function getScanPrompt(type) {
  if (type === 'url') return 'Determine if SAFE, DANGEROUS, PHISHING, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phishing') return 'Determine if PHISHING, SAFE, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phone') return 'Determine if SPAM, FRAUD, or SAFE. Reply ONLY in JSON.';
  if (type === 'upi') return 'Determine if FRAUD, SUSPICIOUS, or SAFE. Reply ONLY in JSON.';
  return 'You are an Indian scam detection expert. Determine if SCAM, FRAUD, or SAFE. Reply ONLY in JSON.';
}

// ============= FORMAT RESULT FOR WHATSAPP =============
function formatWhatsAppResult(result) {
  if (result.confidence && result.confidence > 0 && result.confidence <= 1) {
    result.confidence = Math.round(result.confidence * 100);
  }

  const verdict = (result.verdict || 'UNCERTAIN').toUpperCase();
  const emoji = ['DANGEROUS','SCAM','FRAUD','PHISHING'].includes(verdict) ? '🔴' :
                ['SUSPICIOUS','MISLEADING'].includes(verdict) ? '⚠️' : '✅';
  const status = ['DANGEROUS','SCAM'].includes(verdict) ? 'Dangerous' :
                 ['SUSPICIOUS','MISLEADING'].includes(verdict) ? 'Suspicious' : 'Safe';

  let text = `${emoji} *${status}*\n`;
  if (result.scamType) text += `📋 Type: ${result.scamType}\n`;
  text += `📊 Confidence: ${result.confidence || 'N/A'}%\n`;

  if (result.analysis) text += `\n🔍 ${result.analysis}\n`;

  const findings = Array.isArray(result.findings) ? result.findings : [];
  if (findings.length > 0) {
    text += '\n💡 Findings:';
    findings.forEach(f => text += `\n• ${f}`);
  }

  const whatToDo = Array.isArray(result.whatToDo) ? result.whatToDo : [];
  if (whatToDo.length > 0) {
    text += '\n\n🛡️ What to Do:';
    whatToDo.forEach(w => text += `\n• ${w}`);
  }

  text += '\n\n🌐 _Check more at https://verify-pulse.vercel.app_';
  return text;
}
