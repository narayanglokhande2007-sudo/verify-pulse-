export default function handler(req, res) {
  const VERIFY_TOKEN = 'verifypulse_webhook_2024';  // directly hardcoded

  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }
    return res.status(200).send('WhatsApp route is alive!');
  }

  res.status(200).send('POST ok');
}
