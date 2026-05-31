import json
import urllib.request
import os
from datetime import datetime

# Master file where all data is stored (This grows indefinitely up to 1 Crore)
MASTER_FILE = 'pipeline/daily-data/all_scams_master.jsonl'
# The fast-access JSON file your AI backend actually reads
LATEST_FILE = 'pipeline/daily-data/latest_scams.json'

os.makedirs(os.path.dirname(MASTER_FILE), exist_ok=True)

# List of open-source bulk datasets (Threat Intelligence Feeds)
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
    "https://urlhaus.abuse.ch/downloads/text_recent/",
    "https://raw.githubusercontent.com/PolishCERT/CERT-PL-Warning-List/master/warning_list_domains.txt",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklist.txt"
]

# Indian specific filters
INDIAN_KEYWORDS = [
    'sbi', 'hdfc', 'icici', 'axisbank', 'pnb', 'paytm', 'phonepe', 
    'zerodha', 'groww', 'upstox', 'angelone', 'bse', 'nse',
    'kbc', 'lottery', 'jio', 'airtel', 'vi', 'bsnl',
    'aadhar', 'pan card', 'kyc', 'electricity bill', 'mahavitaran',
    '.in', '.co.in', 'gov.in', 'nic.in', 'india'
]

def is_indian_context(url_or_text):
    lower_text = url_or_text.lower()
    return any(keyword in lower_text for keyword in INDIAN_KEYWORDS)

def append_to_master(data_item):
    with open(MASTER_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(data_item) + '\n')

def update_latest_file(new_urls):
    # Load existing latest_scams.json
    latest = []
    if os.path.exists(LATEST_FILE):
        try:
            with open(LATEST_FILE, 'r', encoding='utf-8') as f:
                latest = json.load(f)
        except:
            pass
    
    # Add new urls to the front
    updated_latest = new_urls + latest
    
    # Deduplicate while preserving order (so newest stay at the top)
    seen = set()
    deduped = [x for x in updated_latest if not (x in seen or seen.add(x))]
    
    # Keep only the latest 200 records in this specific file 
    # so your AI backend fetching it doesn't slow down!
    final_latest = deduped[:200]
    
    with open(LATEST_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_latest, f, indent=2)

def fetch_and_process():
    print(f"[{datetime.now()}] Starting Bulk Dataset Fetcher for Indian Scams...")
    
    # Load existing to avoid duplicates in master
    existing_urls = set()
    if os.path.exists(MASTER_FILE):
        with open(MASTER_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    existing_urls.add(json.loads(line).get('url', ''))
                except:
                    pass

    new_urls_added = []

    for feed_url in FEEDS:
        print(f"Fetching from dataset: {feed_url}")
        try:
            req = urllib.request.Request(feed_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8')
                
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                        
                    url = line
                    
                    if url not in existing_urls:
                        # FILTER: Only keep it if it targets India
                        if is_indian_context(url):
                            append_to_master({
                                "url": url,
                                "source": feed_url,
                                "type": "Phishing/Scam",
                                "date_added": datetime.now().isoformat()
                            })
                            existing_urls.add(url)
                            new_urls_added.append(url)
                            
        except Exception as e:
            print(f"Failed to fetch {feed_url}: {e}")

    # Update the fast-access JSON used by the frontend/AI
    if new_urls_added:
        update_latest_file(new_urls_added)

    print(f"✅ Successfully added {len(new_urls_added)} new Indian-specific scam records today.")
    print(f"Total records in master dataset: {len(existing_urls)}")

if __name__ == '__main__':
    fetch_and_process()
