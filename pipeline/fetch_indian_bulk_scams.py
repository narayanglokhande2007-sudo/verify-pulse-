import json
import urllib.request
import os
import zipfile
from datetime import datetime, timedelta

MASTER_FILE = 'pipeline/daily-data/all_scams_master.jsonl'
LATEST_FILE = 'pipeline/daily-data/latest_scams.json'
ARCHIVE_DIR = 'pipeline/daily-data/archives'

os.makedirs(os.path.dirname(MASTER_FILE), exist_ok=True)
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
    "https://raw.githubusercontent.com/curbengh/phishing-filter/master/domains.txt"
]

INDIAN_KEYWORDS = [
    'sbi', 'hdfc', 'icici', 'axisbank', 'pnb', 'paytm', 'phonepe', 
    'zerodha', 'groww', 'upstox', 'angelone', 'bse', 'nse',
    'kbc', 'lottery', 'jio', 'airtel', 'vi', 'bsnl',
    'aadhar', 'pan card', 'kyc', 'electricity bill', 'mahavitaran',
    '.in', '.co.in', 'gov.in', 'nic.in', 'india'
]

# SAFELIST: Sites that should NEVER be blocked even if a feed makes a mistake
SAFELIST = [
    'google.com', 'facebook.com', 'amazon.in', 'flipkart.com', 'youtube.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'pnbindia.in',
    'paytm.com', 'phonepe.com', 'npci.org.in', 'gov.in', 'uidai.gov.in',
    'wikipedia.org', 'twitter.com', 'x.com', 'instagram.com', 'whatsapp.com'
]

def is_safelisted(url):
    lower_url = url.lower()
    return any(safe_site in lower_url for safe_site in SAFELIST)

def is_indian_context(url_or_text):
    lower_text = url_or_text.lower()
    return any(keyword in lower_text for keyword in INDIAN_KEYWORDS)

def append_to_master(data_item):
    with open(MASTER_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(data_item) + '\n')

def update_latest_file(new_urls):
    latest = []
    if os.path.exists(LATEST_FILE):
        try:
            with open(LATEST_FILE, 'r', encoding='utf-8') as f:
                latest = json.load(f)
        except:
            pass
    
    updated_latest = new_urls + latest
    seen = set()
    deduped = [x for x in updated_latest if not (x in seen or seen.add(x))]
    
    final_latest = deduped[:200]
    
    with open(LATEST_FILE, 'w', encoding='utf-8') as f:
        json.dump(final_latest, f, indent=2)

def archive_old_data():
    if not os.path.exists(MASTER_FILE):
        return
        
    cutoff_date = datetime.now() - timedelta(days=90)
    retained_records = []
    archived_records = []
    
    with open(MASTER_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line)
                date_str = data.get('date_added')
                if date_str:
                    record_date = datetime.fromisoformat(date_str)
                    if record_date < cutoff_date:
                        archived_records.append(data)
                    else:
                        retained_records.append(data)
                else:
                    retained_records.append(data)
            except:
                pass
                
    if archived_records:
        archive_filename = f"archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        archive_path = os.path.join(ARCHIVE_DIR, archive_filename)
        
        with open(archive_path, 'w', encoding='utf-8') as f:
            for rec in archived_records:
                f.write(json.dumps(rec) + '\n')
                
        zip_path = archive_path.replace('.jsonl', '.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(archive_path, arcname=archive_filename)
            
        os.remove(archive_path)
        
        with open(MASTER_FILE, 'w', encoding='utf-8') as f:
            for rec in retained_records:
                f.write(json.dumps(rec) + '\n')
                
        print(f"📦 Archived {len(archived_records)} old records to {zip_path}")

def fetch_and_process():
    print(f"[{datetime.now()}] Starting Mission 20 Data Source Fetcher...")
    
    archive_old_data()
    
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
                content = response.read().decode('utf-8', errors='ignore')
                
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    parts = line.split()
                    if len(parts) > 1 and parts[0] in ['0.0.0.0', '127.0.0.1']:
                        url = parts[1]
                    else:
                        url = parts[0]
                    
                    if url not in existing_urls:
                        if is_safelisted(url):
                            continue
                            
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

    if new_urls_added:
        update_latest_file(new_urls_added)

    print(f"✅ Successfully added {len(new_urls_added)} new Indian-specific scam records today.")
    print(f"Total active records in master dataset: {len(existing_urls)}")

if __name__ == '__main__':
    fetch_and_process()
