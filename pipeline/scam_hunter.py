import json
import urllib.request
import sqlite3
import re
import os
from datetime import datetime

# File Paths
DB_FILE = 'pipeline/daily-data/scams.db'
INDIA_MASTER = 'pipeline/daily-data/india_scams.jsonl'
GLOBAL_MASTER = 'pipeline/daily-data/global_scams.jsonl'

# Keywords for Proactive Hunting (Indian Focus)
HUNT_KEYWORDS = [
    'sbi-kyc', 'hdfc-netbanking', 'paytm-reward', 'phonepe-cashback',
    'kbc-lottery', 'jio-offer', 'free-recharge', 'digital-arrest',
    'mumbai-police-fine', 'fedex-parcel', 'customs-duty-pay'
]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scams 
                 (url TEXT PRIMARY KEY, source TEXT, type TEXT, date_added TEXT, region TEXT)''')
    conn.commit()
    return conn

def is_indian_context(url):
    INDIAN_KEYWORDS = ['sbi', 'hdfc', 'paytm', 'kbc', 'jio', '.in', '.co.in', 'india']
    return any(k in url.lower() for k in INDIAN_KEYWORDS)

def hunt_new_domains():
    """
    Simulates hunting by checking recent certificate transparency logs (via crt.sh)
    for keywords related to Indian scams.
    """
    print(f"[{datetime.now()}] Starting Proactive Scam Hunting...")
    conn = init_db()
    c = conn.cursor()
    
    new_hunts = 0
    for keyword in HUNT_KEYWORDS:
        print(f"Hunting for: {keyword}")
        try:
            # Query crt.sh for recent certificates matching our keywords
            # Using a simple URL request to their JSON API
            search_url = f"https://crt.sh/?q={keyword}&output=json"
            req = urllib.request.Request(search_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                for entry in data[:20]: # Check top 20 recent ones
                    domain = entry['common_name']
                    # Clean domain
                    domain = domain.replace('*.', '')
                    
                    # Verify if it's already in our DB
                    c.execute("SELECT url FROM scams WHERE url LIKE ?", (f"%{domain}%",))
                    if not c.fetchone():
                        # It's a new suspicious domain!
                        region = 'india' if is_indian_context(domain) else 'global'
                        full_url = f"https://{domain}"
                        
                        # Add to DB and JSONL
                        c.execute("INSERT OR IGNORE INTO scams (url, source, type, date_added, region) VALUES (?, ?, ?, ?, ?)",
                                  (full_url, "Autonomous Hunter (CT Logs)", "Proactive Phishing", datetime.now().isoformat(), region))
                        
                        file_path = INDIA_MASTER if region == 'india' else GLOBAL_MASTER
                        with open(file_path, 'a', encoding='utf-8') as f:
                            f.write(json.dumps({"url": full_url, "source": "Autonomous Hunter", "type": "Proactive Phishing", "date_added": datetime.now().isoformat()}) + '\n')
                        
                        new_hunts += 1
            conn.commit()
        except Exception as e:
            print(f"Hunt failed for {keyword}: {e}")
            
    print(f"✅ Hunting Complete! Found {new_hunts} new suspicious domains before they were reported.")
    conn.close()

if __name__ == '__main__':
    hunt_new_domains()
