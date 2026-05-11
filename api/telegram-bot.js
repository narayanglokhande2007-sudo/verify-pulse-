export default async function handler(req, res) {
  if (req.method === 'GET') {
    return res.status(200).send('VerifyPulse Bot is running! 🚀');
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let body;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  const { message } = body || {};
  if (!message || !message.text) {
    return res.status(200).send('ok');
  }

  const chatId = message.chat.id;
  const userText = message.text.trim();
  const BOT_TOKEN = process.env.VERIFYPULSE_BOT_TOKEN;

  try {
    if (userText.startsWith('/start')) {
      await sendTelegramMessage(chatId, '👋 Welcome to VerifyPulse Bot!\n\nSend me any suspicious message, link, or email. I will check if it is a scam.\n\nCommands:\n/score - Check your safety score\n/help - Get help');
      return res.status(200).send('ok');
    }

    if (userText.startsWith('/score')) {
      await sendTelegramMessage(chatId, '🛡️ Safety Score\n\nYour score helps you track your scam awareness.\n\n📊 Visit our website to see your personalized safety score:\nhttps://verify-pulse.vercel.app\n\nStay vigilant! 🛡️');
      return res.status(200).send('ok');
    }

    if (userText.startsWith('/help')) {
      await sendTelegramMessage(chatId, '🔍 VerifyPulse Bot Help\n\n• Send me any message or link to check if it is a scam\n• Use /score to learn about safety scores\n• Visit https://verify-pulse.vercel.app for all 8 tools\n\nStay safe! 🛡️');
      return res.status(200).send('ok');
    }

    await sendTelegramMessage(chatId, '⏳ Scanning... Please wait.');

    const scanResult = await scanInput(userText);
    const resultText = formatResult(scanResult);
    await sendTelegramMessage(chatId, resultText);

  } catch (error) {
    await sendTelegramMessage(chatId, '❌ Error: ' + error.message);
  }

  return res.status(200).send('ok');
}

async function sendTelegramMessage(chatId, text) {
  const BOT_TOKEN = process.env.VERIFYPULSE_BOT_TOKEN;
  await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true })
  });
}

async function scanInput(input) {
  let checkType = 'scam';
  if (input.startsWith('http://') || input.startsWith('https://')) checkType = 'url';
  else if (/^[\d\s\-+()]{10,15}$/.test(input.replace(/[\s\-()]/g, ''))) checkType = 'phone';
  else if (input.includes('@')) {
    if (/@(okhdfc|oksbi|okicici|okaxis|paytm|upi)/i.test(input)) checkType = 'upi';
    else if (/(Subject:|Dear|verify|login|password|account)/i.test(input)) checkType = 'phishing';
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;
  const systemPrompt = getPrompt(checkType);

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
    if (!content) throw new Error('Empty AI response');

    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch {
      const match = content.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
      else throw new Error('No JSON found in AI response');
    }

    return parsed;

  } catch (e) {
    return {
      verdict: 'UNCERTAIN',
      scamType: 'Unknown',
      confidence: 50,
      analysis: 'Scan temporarily unavailable. Try again shortly.',
      findings: ['Service interruption'],
      whatToDo: ['Wait a moment and try again']
    };
  }
}

function getPrompt(type) {
  if (type === 'url') return 'Determine if SAFE, DANGEROUS, PHISHING, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phishing') return 'Determine if PHISHING, SAFE, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phone') return 'Determine if SPAM, FRAUD, or SAFE. Reply ONLY in JSON.';
  if (type === 'upi') return 'Determine if FRAUD, SUSPICIOUS, or SAFE. Reply ONLY in JSON.';
  return 'You are an Indian scam detection expert. Determine if SCAM, FRAUD, or SAFE. Reply ONLY in JSON.';
}

function formatResult(result) {
  // Fix confidence scale
  if (result.confidence && result.confidence > 0 && result.confidence <= 1) {
    result.confidence = Math.round(result.confidence * 100);
  }

  const verdict = (result.verdict || 'UNCERTAIN').toUpperCase();
  const emoji = ['DANGEROUS','SCAM','FRAUD','PHISHING'].includes(verdict) ? '🔴' :
                ['SUSPICIOUS','MISLEADING'].includes(verdict) ? '⚠️' : '✅';
  const status = ['DANGEROUS','SCAM'].includes(verdict) ? 'Dangerous' :
                 ['SUSPICIOUS','MISLEADING'].includes(verdict) ? 'Suspicious' : 'Safe';

  let text = `${emoji} Status: ${status}`;
  if (result.scamType) text += `\n📋 Type: ${result.scamType}`;
  text += `\n📊 Confidence: ${result.confidence || 'N/A'}%`;

  if (result.analysis) text += `\n\n🔍 Analysis:\n${result.analysis}`;

  let findings = result.findings || [];
  if (typeof findings === 'string') findings = [findings];
  if (Array.isArray(findings) && findings.length) {
    text += '\n\n💡 Findings:';
    findings.forEach(f => text += `\n• ${f}`);
  }

  let whatToDo = result.whatToDo || [];
  if (typeof whatToDo === 'string') whatToDo = [whatToDo];
  if (Array.isArray(whatToDo) && whatToDo.length) {
    text += '\n\n🛡️ What to Do:';
    whatToDo.forEach(w => text += `\n• ${w}`);
  }

  text += '\n\n🌐 Check more at https://verify-pulse.vercel.app';
  return text;
}
