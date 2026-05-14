export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'verifypulse_webhook_2024';
  const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
  const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const MY_WHATSAPP_NUMBER = '+919373568817'; // apna number yahan dalo

  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(200).send('WhatsApp route is alive!');
  }

  if (req.method === 'POST') {
    // Test: Bina payload parse kiye seedha apne number par welcome message bhejo
    await sendWhatsAppMessage(MY_WHATSAPP_NUMBER, '✅ Bot POST received. Your number is working!');
    return res.status(200).send('ok');
  }

  // Real message handling part (baad mein chalega)
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    // ... rest of message handling (abhi test nahi karenge)
  } catch (e) { return res.status(200).send('ok'); }
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
