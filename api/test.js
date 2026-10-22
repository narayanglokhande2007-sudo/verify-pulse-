import { sanitizeForExternalAnalysis } from '../lib/privacy_guard.js';

export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
  const MY_NUMBER = process.env.ADMIN_WHATSAPP_NUMBER || '';

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
    let from;
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const message = body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0];

      if (!message || message.from === MY_NUMBER) {
        return res.status(200).send('ok');
      }

      from = message.from;
      let userText = '';
      if (message.type === 'text') {
        userText = message.text?.body || '';
      } else {
        userText = `[${message.type} received]`;
      }

      if (!userText) return res.status(200).send('ok');

      // Commands handle karna
      if (userText.startsWith('/start')) {
        await sendWhatsAppMessage(from, '👋 Welcome to VerifyPulse Bot on WhatsApp!\n\nSend me any suspicious message, link, or email. I will check if it is a scam.');
        return res.status(200).send('ok');
      }
      if (userText.startsWith('/help')) {
        await sendWhatsAppMessage(from, '🔍 VerifyPulse Bot Help\n\n• Send me any message or link\n• Visit verify-pulse.vercel.app');
        return res.status(200).send('ok');
      }
      if (userText.startsWith('/score')) {
        await sendWhatsAppMessage(from, '🛡️ Safety Score\n\nVisit our website to see your safety score:\nhttps://verify-pulse.vercel.app');
        return res.status(200).send('ok');
      }

      await sendWhatsAppMessage(from, '⏳ Scanning... Please wait.');
      const result = await scanText(userText);
      const reply = formatResult(result);
      await sendWhatsAppMessage(from, reply);
      return res.status(200).send('ok');

    } catch (error) {
      if (from) {
        try { await sendWhatsAppMessage(from, '⚠️ Service temporarily busy. Please try again shortly or visit https://verify-pulse.vercel.app'); } catch (e) {}
      }
      return res.status(200).send('ok');
    }
  }

  return res.status(405).send('Method not allowed');
}

// --- Helper Functions ---
async function sendWhatsAppMessage(to, text) {
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
  if (!ACCESS_TOKEN || !PHONE_NUMBER_ID || !to) return;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);
    await fetch(`https://graph.facebook.com/v25.0/${PHONE_NUMBER_ID}/messages`, {
      method: 'POST',
      signal: controller.signal,
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
    clearTimeout(timeoutId);
  } catch {}
}

async function scanText(input) {
  const cleanInput = sanitizeForExternalAnalysis(input);
  let checkType = 'scam';
  if (cleanInput.startsWith('http')) checkType = 'url';
  else if (/^[\d\s\-+()]{10,15}$/.test(cleanInput.replace(/[\s\-()]/g, ''))) checkType = 'phone';
  else if (cleanInput.includes('@')) {
    if (/@(okhdfc|oksbi|okicici|okaxis|paytm|upi)/i.test(cleanInput)) checkType = 'upi';
    else if (/(verify|login|password|account|subject:|dear)/i.test(cleanInput)) checkType = 'phishing';
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const GROQ_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';

  if (!GROQ_KEY) {
    return {
      verdict: 'UNCERTAIN',
      scamType: 'Scan Pending',
      confidence: 50,
      analysis: 'AI scan engine pending configuration. Please visit https://verify-pulse.vercel.app for real-time verification.',
      findings: ['AI credentials pending configuration'],
      whatToDo: ['Visit verify-pulse.vercel.app to check suspicious messages']
    };
  }

  const systemPrompt = getScanPrompt(checkType);
  let timeoutId = null;

  try {
    const controller = new AbortController();
    timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Authorization': `Bearer ${GROQ_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages: [
          { role: 'system', content: 'You are a cybersecurity AI. Always respond in valid JSON. Format: {"verdict":"SCAM/SAFE","scamType":"...","confidence":85,"analysis":"...","findings":["point1","point2"],"whatToDo":["step1","step2"]}' },
          { role: 'user', content: systemPrompt + '\n\nInput: "' + cleanInput + '"' }
        ],
        temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
      })
    });
    clearTimeout(timeoutId);

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
  } catch (error) {
    return {
      verdict: 'UNCERTAIN',
      scamType: 'Service Interruption',
      confidence: 50,
      analysis: 'Scan temporarily unavailable. Please try again or visit https://verify-pulse.vercel.app',
      findings: ['Service interruption'],
      whatToDo: ['Wait a moment and try again', 'Visit verify-pulse.vercel.app']
    };
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
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
  // Confidence scale fix
  if (result.confidence > 0 && result.confidence <= 1) {
    result.confidence = Math.round(result.confidence * 100);
  }

  const verdict = (result.verdict || '').toUpperCase();
  const emoji = ['DANGEROUS','SCAM','FRAUD','PHISHING'].includes(verdict) ? '🔴' :
                ['SUSPICIOUS','MISLEADING'].includes(verdict) ? '⚠️' : '✅';
  const status = ['DANGEROUS','SCAM'].includes(verdict) ? 'Dangerous' :
                 ['SUSPICIOUS','MISLEADING'].includes(verdict) ? 'Suspicious' : 'Safe';

  let text = `${emoji} *${status}*\n📋 Type: ${result.scamType || 'N/A'}\n📊 Confidence: ${result.confidence || 'N/A'}%\n\n🔍 ${result.analysis || ''}`;

  // Safe handling for findings and whatToDo (string or array)
  let findings = result.findings || [];
  if (typeof findings === 'string') findings = [findings];
  if (Array.isArray(findings)) {
    findings.forEach(f => text += `\n• ${f}`);
  }

  let whatToDo = result.whatToDo || [];
  if (typeof whatToDo === 'string') whatToDo = [whatToDo];
  if (Array.isArray(whatToDo)) {
    text += '\n\n🛡️ *What to Do:*';
    whatToDo.forEach(w => text += `\n• ${w}`);
  }

  return text + '\n\n🌐 verify-pulse.vercel.app';
    }
