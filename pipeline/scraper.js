const https = require('https');
const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');
const OPENPHISH_URL = 'https://openphish.com/feed.txt';

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'VerifyPulseBot/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log(`Status: ${res.statusCode}`);
        console.log(`Headers: ${JSON.stringify(res.headers)}`);
        console.log(`Data length: ${data.length}`);
        console.log(`First 200 chars: ${data.substring(0, 200)}`);
        resolve(data);
      });
    }).on('error', reject);
  });
}

async function fetchOpenPhishScams() {
  const scams = [];
  try {
    const text = await fetchText(OPENPHISH_URL);
    if (!text) {
      console.log('Response was empty.');
      return scams;
    }
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    console.log(`Total lines: ${lines.length}`);
    const urls = lines.filter(l => l.startsWith('http'));
    console.log(`URLs after filter: ${urls.length}`);
    scams.push(...urls);
  } catch (e) {
    console.error(`OpenPhish error: ${e.message}`);
  }
  return scams;
}

(async () => {
  try {
    let existing = [];
    if (fs.existsSync(SCAM_FILE)) {
      existing = JSON.parse(fs.readFileSync(SCAM_FILE, 'utf8'));
    }

    const newScams = await fetchOpenPhishScams();
    const all = [...new Set([...existing, ...newScams])];

    fs.writeFileSync(SCAM_FILE, JSON.stringify(all, null, 2));
    console.log(`\n✅ Total scams saved: ${all.length} (${newScams.length} new)`);
  } catch (e) {
    console.error('❌ Fatal scraper error:', e.message);
    process.exit(1);
  }
})();
