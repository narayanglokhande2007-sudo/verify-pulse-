export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'verifypulse_webhook_2024';
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;

  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(200).send('WhatsApp route is alive!');
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const entries = body?.entry;
    if (!entries) return res.status(200).send('ok');

    for (const entry of entries) {
      const changes = entry?.changes;
      if (!changes) continue;
      for (const change of changes) {
        const messages = change?.value?.messages;
        if (!messages) continue;
        for (const message of messages) {
          const from = message.from;
          let text = '';
          if (message.type === 'text') {
            text = message.text?.body || '';
          } else {
            text = `[${message.type} received]`;
          }
          if (text) {
            const result = await scanText(text);
            const reply = formatResult(result);
            await sendWhatsAppMessage(from, reply);
          }
        }
      }
    }
    return res.status(200).send('ok');
  } catch (error) {
    return res.status(200).send('ok');
  }
}

async function sendWhatsAppMessage(to, text) {
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
  await fetch(`https://graph.facebook.com/v25.0/${PHONE_NUMBER_ID}/messages`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${ACCESS_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ messaging_product: 'whatsapp', to, type: 'text', text: { body: text } })
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
  const systemPrompt = getPrompt(checkType);
  try {
    const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'You are a cybersecurity AI. Reply ONLY in JSON: {"verdict":"...", "scamType":"...", "confidence":85, "analysis":"...", "findings":[], "whatToDo":[]}' },
          { role: 'user', content: systemPrompt + '\n\nInput: "' + input + '"' }
        ], temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
      })
    });
    const data = await resp.json();
    const content = data.choices?.[0]?.message?.content;
    if (content) {
      try { return JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); }
    }
  } catch (e) {}
  return { verdict: 'UNCERTAIN', scamType: 'Unknown', confidence: 50, analysis: 'Scan failed. Please try again.', findings: [], whatToDo: ['Try again later'] };
}

function getPrompt(type) {
  if (type === 'url') return 'Determine if SAFE, DANGEROUS, PHISHING, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phishing') return 'Determine if PHISHING, SAFE, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phone') return 'Determine if SPAM, FRAUD, or SAFE. Reply ONLY in JSON.';
  if (type === 'upi') return 'Determine if FRAUD, SUSPICIOUS, or SAFE. Reply ONLY in JSON.';
  return 'You are an Indian scam detection expert. Determine if SCAM, FRAUD, or SAFE. Reply ONLY in JSON.';
}

function formatResult(result) {
  if (result.confidence > 0 && result.confidence <= 1) result.confidence = Math.round(result.confidence * 100);
  const v = (result.verdict || '').toUpperCase();
  const emoji = ['DANGEROUS','SCAM','FRAUD','PHISHING'].includes(v) ? '🔴' : ['SUSPICIOUS','MISLEADING'].includes(v) ? '⚠️' : '✅';
  const status = ['DANGEROUS','SCAM'].includes(v) ? 'Dangerous' : ['SUSPICIOUS','MISLEADING'].includes(v) ? 'Suspicious' : 'Safe';
  let text = `${emoji} *${status}*\n📋 Type: ${result.scamType || 'N/A'}\n📊 Confidence: ${result.confidence || 'N/A'}%\n\n🔍 ${result.analysis || ''}`;
  (result.findings || []).forEach(f => text += `\n• ${f}`);
  (result.whatToDo || []).forEach(w => text += `\n🛡️ ${w}`);
  return text + '\n\n🌐 verify-pulse.vercel.app';
      }
