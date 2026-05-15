import fetch from 'node-fetch';
import { promises as fs } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCAM_FILE = path.join(__dirname, 'daily-data', 'latest_scams.json');

async function fetchRedditScams() {
  const subs = ['Scams', 'IndiaScams', 'IsThisAScamIndia'];
  const scams = [];
  for (const sub of subs) {
    try {
      const url = `https://old.reddit.com/r/${sub}/new.json?limit=50`;
      const res = await fetch(url, {
        headers: { 'User-Agent': 'VerifyPulseBot/1.0 (by /u/narayan_lokhande)' }
      });
      if (!res.ok) throw new Error(`Status ${res.status}`);
      const data = await res.json();
      for (const post of data.data?.children || []) {
        const txt = `${post.data?.title || ''} ${post.data?.selftext || ''}`.trim();
        if (txt.length > 30) scams.push(txt);
      }
    } catch (e) {
      console.error(`Reddit ${sub} error: ${e.message}`);
    }
  }
  return scams;
}

(async () => {
  try {
    let existing = [];
    try { existing = JSON.parse(await fs.readFile(SCAM_FILE, 'utf-8')); } catch {}
    const newScams = await fetchRedditScams();
    const all = [...new Set([...existing, ...newScams])];
    await fs.writeFile(SCAM_FILE, JSON.stringify(all, null, 2));
    console.log(`✅ Total scams: ${all.length} (${newScams.length} new)`);
  } catch (err) {
    console.error('❌ Fatal:', err.message);
    process.exit(1);
  }
})();
