export default async function handler(req, res) {
  // GET request for verification
  if (req.method === 'GET') {
    const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN || 'verifypulse_webhook_2024';
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(200).send('WhatsApp route alive');
  }

  // POST request: try to send a WhatsApp message and return result
  if (req.method === 'POST') {
    const MY_NUMBER = '+919373568817'; // <-- यहाँ अपना नंबर डालें
    try {
      const ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
      const PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
      
      // Check if env vars exist
      if (!ACCESS_TOKEN) throw new Error('ACCESS_TOKEN missing');
      if (!PHONE_NUMBER_ID) throw new Error('PHONE_NUMBER_ID missing');

      const url = `https://graph.facebook.com/v25.0/${PHONE_NUMBER_ID}/messages`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${ACCESS_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messaging_product: 'whatsapp',
          to: MY_NUMBER,
          type: 'text',
          text: { body: '✅ POST received' }
        })
      });

      const data = await response.json();
      if (!response.ok) {
        // Return the error from Meta
        return res.status(500).json({ error: 'Meta API error', details: data });
      }
      return res.status(200).json({ success: true, sent: true });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }

  return res.status(405).send('Method not allowed');
}
