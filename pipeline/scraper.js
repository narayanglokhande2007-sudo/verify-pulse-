const https = require('https');
const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: {
        'User-Agent': 'VerifyPulseBot/1.0 (by narayan_lokhande)'
      }
    };
    https.get(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`JSON parse failed. First 100 chars: ${data.substring(0, 100)}`));
        }
      });
    }).on('error', reject);
  });
}

async function fetchRedditScams() {
  const subreddits = ['Scams', 'IndiaScams', 'IsThisAScamIndia'];
  const scams = [];
  for (const sub of subreddits) {
    try {
      const url = `https://old.reddit.com/r/${sub}/new.json?limit=25`;
      const data = await fetchJSON(url);
      const posts = data?.data?.children || [];
      for (const post of posts) {
        const title = post.data?.title || '';
        const selftext = post.data?.selftext || '';
        const combined = (title + ' ' + selftext).trim();
        if (combined.length > 30) scams.push(combined);
      }
      console.log(`✅ /r/${sub}: ${posts.length} posts fetched`);
    } catch (e) {
      console.error(`❌ /r/${sub} failed: ${e.message}`);
    }
  }
  return scams;
}

(async () => {
  try {
    let existing = [];
    if (fs.existsSync(SCAM_FILE)) {
      existing = JSON.parse(fs.readFileSync(SCAM_FILE, 'utf8'));
    }

    const newScams = await fetchRedditScams();
    const all = [...new Set([...existing, ...newScams])];

    fs.writeFileSync(SCAM_FILE, JSON.stringify(all, null, 2));
    console.log(`\n✅ Total scams saved: ${all.length} (${newScams.length} new)`);
  } catch (e) {
    console.error('❌ Fatal scraper error:', e.message);
    process.exit(1);
  }
})();
