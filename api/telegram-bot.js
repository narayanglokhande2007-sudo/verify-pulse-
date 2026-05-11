export default async function handler(req, res) {
  if (req.method === 'GET') {
    return res.status(200).send('VerifyPulse Bot is running! 🚀');
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { message } = req.body;

  if (!message || !message.text) {
    return res.status(200).send('ok');
  }

  const chatId = message.chat.id;
  const userText = message.text.trim();

  const BOT_TOKEN = process.env.VERIFYPULSE_BOT_TOKEN;
  const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

  try {
    // /start command
    if (userText.startsWith('/start')) {
      await sendMessage(chatId, 
        '👋 Welcome to VerifyPulse Bot!\n\n' +
        'Send me any suspicious message, link, or email. I will check if it is a scam.\n\n' +
        'Commands:\n' +
        '/score - Check your safety score\n' +
        '/help - Get help'
      );
      return res.status(200).send('ok');
    }

    // /score command
    if (userText.startsWith('/score')) {
      await sendMessage(chatId, 
        '🛡️ Safety Score\n\n' +
        'Your score helps you track your scam awareness.\n\n' +
        '📊 Visit our website to see your personalized safety score:\n' +
        'https://verify-pulse.vercel.app\n\n' +
        'Stay vigilant! 🛡️'
      );
      return res.status(200).send('ok');
    }

    // /help command
    if (userText.startsWith('/help')) {
      await sendMessage(chatId, 
        '🔍 VerifyPulse Bot Help\n\n' +
        '• Send me any message or link to check if it is a scam\n' +
        '• Use /score to learn about safety scores\n' +
        '• Visit https://verify-pulse.vercel.app for all 8 tools\n\n' +
        'Stay safe! 🛡️'
      );
      return res.status(200).send('ok');
    }

    // Scanning message
    await sendMessage(chatId, '⏳ Scanning... Please wait.');

    // AI scan
    const scanResult = await scanInput(userText);
    const resultText = formatResult(scanResult);
    await sendMessage(chatId, resultText);

  } catch (error) {
    console.error('Bot error:', error);
    await sendMessage(chatId, '❌ Sorry, something went wrong. Please try again.');
  }

  return res.status(200).send('ok');
}

async function sendMessage(chatId, text) {
  const BOT_TOKEN = process.env.VERIFYPULSE_BOT_TOKEN;
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;

  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: text,
      disable_web_page_preview: true
    })
  });
}

async function scanInput(input) {
  let checkType = 'scam';
  if (input.startsWith('http://') || input.startsWith('https://')) {
    checkType = 'url';
  } else if (input.includes('@')) {
    if (/@(okhdfc|oksbi|okicici|okaxis|paytm|upi)/i.test(input)) {
      checkType = 'upi';
    } else if (/(Subject:|Dear|verify|login|password|account)/i.test(input)) {
      checkType = 'phishing';
    }
  } else if (/^\+?[\d\s\-()]{10,15}$/.test(input.replace(/[\s\-()]/g, ''))) {
    checkType = 'phone';
  }

  const GROQ_KEY = process.env.GROQ_API_KEY;

  try {
    const systemPrompt = getPrompt(checkType);
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${GROQ_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'You are a cybersecurity and scam-detection AI. Always respond in valid JSON format with keys: verdict, scamType, confidence, analysis, findings, whatToDo.' },
          { role: 'user', content: systemPrompt + `\n\nInput: "${input}"` }
        ],
        temperature: 0.2, max_tokens: 500, response_format: { type: "json_object" }
      })
    });
    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    if (content) {
      let parsed;
      try { parsed = JSON.parse(content); } catch { const m = content.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else throw new Error('Invalid JSON'); }
      return parsed;
    }
  } catch (e) {}

  return {
    verdict: 'UNCERTAIN',
    scamType: 'Unknown',
    confidence: 50,
    analysis: 'Unable to analyze right now. Please try again.',
    findings: [],
    whatToDo: ['Be cautious']
  };
}

function getPrompt(type) {
  if (type === 'url') return 'You are a URL safety expert. Determine if SAFE, DANGEROUS, PHISHING, or SUSPICIOUS. Reply ONLY in JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.';
  if (type === 'phishing') return 'You are an anti-phishing AI. Determine if PHISHING, SAFE, or SUSPICIOUS. Reply ONLY in JSON.';
  if (type === 'phone') return 'You are a phone fraud detector. Determine if SPAM, FRAUD, or SAFE. Reply ONLY in JSON.';
  if (type === 'upi') return 'You are a UPI fraud detector. Determine if FRAUD, SUSPICIOUS, or SAFE. Reply ONLY in JSON.';
  return 'You are an Indian scam detection expert. Analyze and return JSON with keys: verdict, scamType, confidence, analysis, findings, whatToDo.';
}

function formatResult(result) {
  const v = (result.verdict || '').toUpperCase();
  let emoji = '✅';
  let status = 'Safe';

  if (['DANGEROUS','SCAM','FRAUD','PHISHING'].includes(v)) {
    emoji = '🔴';
    status = 'Dangerous';
  } else if (['SUSPICIOUS','MISLEADING'].includes(v)) {
    emoji = '⚠️';
    status = 'Suspicious';
  }

  let text = `${emoji} Status: ${status}`;
  if (result.scamType) text += `\n📋 Type: ${result.scamType}`;
  text += `\n📊 Confidence: ${result.confidence || 'N/A'}%`;

  if (result.analysis) {
    text += `\n\n🔍 Analysis:\n${result.analysis}`;
  }

  if (result.findings && result.findings.length > 0) {
    text += '\n\n💡 Findings:';
    result.findings.forEach(f => text += `\n• ${f}`);
  }

  if (result.whatToDo && result.whatToDo.length > 0) {
    text += '\n\n🛡️ What to Do:';
    result.whatToDo.forEach(w => text += `\n• ${w}`);
  }

  text += '\n\n🌐 Check more at https://verify-pulse.vercel.app';
  return text;
}
