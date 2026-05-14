export default async function handler(req, res) {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'verifypulse_webhook_2024';
  const MY_NUMBER = '+919373568817'; // apna number yahan daalo

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
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const message = body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0];
      
      // Agar sender mai khud hoon, to reply mat bhejo (loop rokne ke liye)
      if (message?.from === MY_NUMBER) {
        return res.status(200).send('ok');
      }

      // Sirf reply bhejo agar sender koi aur hai
      if (message?.from) {
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
            to: message.from,
            type: 'text',
            text: { body: '✅ Message received. AI reply coming soon!' }
          })
        });
      }
      return res.status(200).send('ok');
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  return res.status(405).send('Method not allowed');
}
