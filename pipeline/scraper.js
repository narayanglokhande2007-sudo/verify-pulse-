const https = require('https');
const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'application/json'
      }
    };
    https.get(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('JSON parse failed')); }
      });
    }).on('error', reject);
  });
}

async function fetchRedditScams() {
  const subreddits = ['Scams', 'IndiaScams', 'IsThisAScamIndia'];
  const scams = [];
  for (const sub of subreddits) {
    try {
      const url = `https://old.reddit.com/r/${sub}/new.json?limit=50`;
      const data = await fetchJSON(url);
      const posts = data.data?.children || [];
      for (const post of posts) {
        const title = post.data?.title || '';
        const selftext = post.data?.selftext || '';
        const combined = (title + ' ' + selftext).trim();
        if (combined.length > 20) scams.push(combined);
      }
    } catch (e) {
      console.error(`Reddit ${sub} failed:`, e.message);
    }
  }
  return scams;
}

(async () => {
  try {
    const existing = JSON.parse(fs.readFileSync(SCAM_FILE, 'utf8'));
    const redditScams = await fetchRedditScams();
    const newScams = [...new Set([...existing, ...redditScams])];
    fs.writeFileSync(SCAM_FILE, JSON.stringify(newScams, null, 2));
    console.log(`✅ Scams updated. Total: ${newScams.length}`);
  } catch (e) {
    console.error('❌ Scraper failed:', e);
    process.exit(1);
  }
})();
