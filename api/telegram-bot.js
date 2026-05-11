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
    // Sirf test reply bhejo
    await fetch(`${TELEGRAM_API}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: `You said: ${userText}`
      })
    });

  } catch (error) {
    console.error('Error:', error);
  }

  return res.status(200).send('ok');
}
