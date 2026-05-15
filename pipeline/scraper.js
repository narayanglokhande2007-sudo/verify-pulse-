const https = require('https');
const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');
// Use the final raw URL (no redirect needed)
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'VerifyPulseBot/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

async function fetchOpenPhishScams() {
  const scams = [];
  try {
    const text = await fetchText(OPENPHISH_URL);
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const urls = lines.filter(l => l.startsWith('http'));
    console.log(`OpenPhish URLs found: ${urls.length}`);
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
