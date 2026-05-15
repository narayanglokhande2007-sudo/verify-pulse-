const https = require('https');
const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');
const PHISHTANK_URL = 'http://data.phishtank.com/data/online-valid.json';

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'VerifyPulseBot/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`JSON parse failed. Response was not JSON.`));
        }
      });
    }).on('error', reject);
  });
}

async function fetchPhishTankScams() {
  const scams = [];
  try {
    const entries = await fetchJSON(PHISHTANK_URL);
    console.log(`PhishTank entries fetched: ${entries.length}`);
    for (const entry of entries) {
      if (entry.url) scams.push(entry.url);
    }
  } catch (e) {
    console.error(`PhishTank error: ${e.message}`);
  }
  return scams;
}

(async () => {
  try {
    let existing = [];
    if (fs.existsSync(SCAM_FILE)) {
      existing = JSON.parse(fs.readFileSync(SCAM_FILE, 'utf8'));
    }

    const newScams = await fetchPhishTankScams();
    const all = [...new Set([...existing, ...newScams])];

    fs.writeFileSync(SCAM_FILE, JSON.stringify(all, null, 2));
    console.log(`\n✅ Total scams saved: ${all.length} (${newScams.length} new)`);
  } catch (e) {
    console.error('❌ Fatal scraper error:', e.message);
    process.exit(1);
  }
})();
