import json
import os

MASTER_FILE = 'pipeline/daily-data/all_scams_master.jsonl'
LATEST_FILE = 'pipeline/daily-data/latest_scams.json'
CLEAN_SPAM_FILE = 'clean_spam.json'

def load_json_list(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def append_to_master(url):
    with open(MASTER_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps({'url': url}) + '\n')

def main():
    existing = set()
    if os.path.exists(MASTER_FILE):
        with open(MASTER_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    existing.add(data['url'])
                except:
                    pass

    latest_urls = load_json_list(LATEST_FILE)
    clean_spam = load_json_list(CLEAN_SPAM_FILE)
    all_new = set(latest_urls + clean_spam) - existing
    count = 0
    for url in all_new:
        append_to_master(url)
        count += 1

    print(f"✅ Added {count} new URLs to master training file. Total unique URLs in master: {len(existing) + count}")

if __name__ == '__main__':
    main()
