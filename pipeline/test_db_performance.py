import sqlite3
import time
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(__file__), 'daily-data', 'scams.db')

def test_performance():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Ensure table exists
    c.execute('''CREATE TABLE IF NOT EXISTS scams 
                 (url TEXT PRIMARY KEY, source TEXT, type TEXT, date_added TEXT, region TEXT)''')
    conn.commit()

    # Test insertion speed
    print("\n--- Testing Insertion Speed ---")
    start_time = time.time()
    for i in range(1000):
        url = f"http://test-scam-{i}.com"
        source = "Test"
        scam_type = "Phishing"
        date_added = datetime.now().isoformat()
        region = "global"
        c.execute("INSERT OR IGNORE INTO scams (url, source, type, date_added, region) VALUES (?, ?, ?, ?, ?)",
                  (url, source, scam_type, date_added, region))
    conn.commit()
    end_time = time.time()
    print(f"Inserted 1000 records in {end_time - start_time:.4f} seconds.")

    # Test search speed
    print("\n--- Testing Search Speed ---")
    search_url = "http://test-scam-500.com"
    start_time = time.time()
    c.execute("SELECT * FROM scams WHERE url = ?", (search_url,))
    result = c.fetchone()
    end_time = time.time()
    print(f"Search for '{search_url}' took {end_time - start_time:.4f} seconds. Found: {bool(result)}")

    search_partial = "test-scam-9"
    start_time = time.time()
    c.execute("SELECT * FROM scams WHERE url LIKE ?", (f'%{search_partial}%',))
    results = c.fetchall()
    end_time = time.time()
    print(f"Partial search for '{search_partial}' took {end_time - start_time:.4f} seconds. Found {len(results)} records.")

    conn.close()

if __name__ == '__main__':
    test_performance()
