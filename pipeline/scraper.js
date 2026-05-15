const fs = require('fs');
const path = require('path');

const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');

async function fetchRedditScams() {
  const subreddits = ['Scams', 'IndiaScams', 'IsThisAScamIndia'];
  const scams = [];
  for (const sub of subreddits) {
    try {
      const url = `https://old.reddit.com/r/${sub}/new.json?limit=50`;
      const res = await fetch(url);
      const data = await res.json();
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

async function fetchPhishTank() {
  // Placeholder – API key lagegi. Skip for now.
  return [];
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
