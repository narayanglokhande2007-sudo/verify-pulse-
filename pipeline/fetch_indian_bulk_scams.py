import json
import urllib.request
import os
import zipfile
import sqlite3
from datetime import datetime, timedelta

# File Paths
INDIA_MASTER = 'pipeline/daily-data/india_scams.jsonl'
GLOBAL_MASTER = 'pipeline/daily-data/global_scams.jsonl'
LATEST_FILE = 'pipeline/daily-data/latest_scams.json'
DB_FILE = 'pipeline/daily-data/scams.db'
ARCHIVE_DIR = 'pipeline/daily-data/archives'

os.makedirs(os.path.dirname(INDIA_MASTER), exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)

# EXACTLY 20 Unique Open-Source Feeds
FEEDS = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://phishing.database.red/phishing-links-NEW-today.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "https://vxvault.net/URL_List.php",
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
    "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
    "https://raw.githubusercontent.com/joshua-s/active-phishing-domains/master/active-phishing-domains.txt",
    "https://raw.githubusercontent.com/Dshield-ISC/dshield/master/suspicious_domains.txt",
    "https://raw.githubusercontent.com/PolishCERT/CERT-PL-Warning-List/master/warning_list_domains.txt",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklist.txt",
    "https://v.firebog.net/hosts/Prigent-Phishing.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
    "https://v.firebog.net/hosts/Fraud.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/dogeloverpi/scam-link-dataset/main/scam_links.txt",
    "https://raw.githubusercontent.com/romainbousseau/digitalside-misp-feed/master/lists/latestips.txt",
    "https://curbengh.github.io/phishing-filter/domains.txt"
]

INDIAN_KEYWORDS = [
    'sbi', 'hdfc', 'icici', 'axisbank', 'pnb', 'paytm', 'phonepe', 
    'zerodha', 'groww', 'upstox', 'angelone', 'bse', 'nse',
    'kbc', 'lottery', 'jio', 'airtel', 'vi', 'bsnl',
    'aadhar', 'pan card', 'kyc', 'electricity bill', 'mahavitaran',
    '.in', '.co.in', 'gov.in', 'nic.in', 'india'
]

SAFELIST = [
    'google.com', 'facebook.com', 'amazon.in', 'flipkart.com', 'youtube.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'pnbindia.in',
    'paytm.com', 'phonepe.com', 'npci.org.in', 'gov.in', 'uidai.gov.in',
    'wikipedia.org', 'twitter.com', 'x.com', 'instagram.com', 'whatsapp.com'
]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Table for all scams with a region flag
    c.execute('''CREATE TABLE IF NOT EXISTS scams 
                 (url TEXT PRIMARY KEY, source TEXT, type TEXT, date_added TEXT, region TEXT)''')
    # Index for ultra-fast searching
    c.execute('CREATE INDEX IF NOT EXISTS idx_url ON scams(url)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_region ON scams(region)')
    conn.commit()
    return conn

def is_safelisted(url):
    lower_url = url.lower()
    return any(safe_site in lower_url for safe_site in SAFELIST)

def is_indian_context(url_or_text):
    lower_text = url_or_text.lower()
    return any(keyword in lower_text for keyword in INDIAN_KEYWORDS)

def append_to_storage(data_item, region, conn):
    file_path = INDIA_MASTER if region == 'india' else GLOBAL_MASTER
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(data_item) + '\n')
    
    # Also add to SQLite Watchman
    try:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO scams (url, source, type, date_added, region) VALUES (?, ?, ?, ?, ?)",
                  (data_item['url'], data_item['source'], data_item['type'], data_item['date_added'], region))
        conn.commit()
    except Exception as e:
        print(f"DB Insert Error: {e}")

def update_latest_file(new_urls):
    latest = []
    if os.path.exists(LATEST_FILE):
        try:
            with open(LATEST_FILE, 'r', encoding='utf-8') as f:
                latest = json.load(f)
        except: pass
    
    updated_latest = new_urls + latest
    seen = set()
    deduped = [x for x in updated_latest if not (x in seen or seen.add(x))]
    final_latest = deduped[:200]
    
    with open(LATEST_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_latest, f, indent=2)

def fetch_and_process():
    print(f"[{datetime.now()}] Starting SQLite Watchman Dual-Storage Pipeline...")
    conn = init_db()
    
    # Load existing URLs from DB to avoid duplicates
    c = conn.cursor()
    c.execute("SELECT url FROM scams")
    existing_urls = {row[0] for row in c.fetchall()}

    new_india_urls = []
    new_global_count = 0

    for feed_url in FEEDS:
        print(f"Fetching: {feed_url}")
        try:
            req = urllib.request.Request(feed_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8', errors='ignore')
                for line in content.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    parts = line.split()
                    url = parts[1] if len(parts) > 1 and parts[0] in ['0.0.0.0', '127.0.0.1'] else parts[0]
                    
                    if url not in existing_urls and not is_safelisted(url):
                        region = 'india' if is_indian_context(url) else 'global'
                        data_item = {
                            "url": url,
                            "source": feed_url,
                            "type": "Phishing/Scam",
                            "date_added": datetime.now().isoformat()
                        }
                        append_to_storage(data_item, region, conn)
                        existing_urls.add(url)
                        if region == 'india': new_india_urls.append(url)
                        else: new_global_count += 1
                            
        except Exception as e:
            print(f"Failed {feed_url}: {e}")

    if new_india_urls:
        update_latest_file(new_india_urls)

    print(f"✅ Added {len(new_india_urls)} India records and {new_global_count} Global records.")
    conn.close()

if __name__ == '__main__':
    fetch_and_process()
