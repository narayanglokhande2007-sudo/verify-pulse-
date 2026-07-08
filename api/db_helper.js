const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const DB_FILE = path.join(__dirname, "../pipeline/daily-data/scams.db");
const FALLBACK_CACHE = path.join(__dirname, "../pipeline/daily-data/scam_cache.json");

/**
 * Initializes the SQLite database and creates the 'scams' table if it doesn't exist.
 * This ensures the database is ready for use.
 */
function initDb() {
  const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) {
      console.error("Error connecting to database:", err.message);
    } else {
      console.log("Connected to the SQLite database.");
      db.serialize(() => {
        db.run(
          `CREATE TABLE IF NOT EXISTS scams (
            url TEXT PRIMARY KEY,
            source TEXT,
            type TEXT,
            date_added TEXT,
            region TEXT
          )`
        );
        db.run(
          `CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            category TEXT,
            risk_level TEXT
          )`
        );
        
        // Seed initial brands if table is empty
        db.get("SELECT COUNT(*) as count FROM brands", (err, row) => {
          if (!err && row && row.count === 0) {
            const initialBrands = [
              ['SBI', 'Banking', 'High'],
              ['HDFC', 'Banking', 'High'],
              ['ICICI', 'Banking', 'High'],
              ['Axis', 'Banking', 'High'],
              ['Paytm', 'Fintech', 'High'],
              ['PhonePe', 'Fintech', 'High'],
              ['KBC', 'General', 'Medium'],
              ['Airtel', 'Telecom', 'Medium'],
              ['Jio', 'Telecom', 'Medium'],
              ['Google', 'Tech', 'High'],
              ['Microsoft', 'Tech', 'High'],
              ['Apple', 'Tech', 'High']
            ];
            const stmt = db.prepare("INSERT INTO brands (name, category, risk_level) VALUES (?, ?, ?)");
            initialBrands.forEach(brand => stmt.run(brand));
            stmt.finalize();
          }
        });
      });
    }
  });
  return db;
}

/**
 * Fetches the list of brands from the database for dynamic intelligence.
 */
async function getBrands() {
  const db = initDb();
  return new Promise((resolve, reject) => {
    db.all("SELECT name FROM brands", (err, rows) => {
      db.close();
      if (err) {
        console.error("Error fetching brands:", err.message);
        return resolve(['SBI', 'HDFC', 'Paytm', 'PhonePe', 'Google', 'Microsoft', 'Apple']); // Fallback
      }
      resolve(rows.map(row => row.name));
    });
  });
}

/**
 * Adds a new brand to the dynamic intelligence database.
 */
async function addBrand(name, category = 'General', riskLevel = 'Medium') {
  const db = initDb();
  return new Promise((resolve, reject) => {
    db.run("INSERT OR IGNORE INTO brands (name, category, risk_level) VALUES (?, ?, ?)", 
      [name, category, riskLevel], function(err) {
      db.close();
      if (err) return reject(err);
      resolve({ success: true, id: this.lastID });
    });
  });
}

/**
 * Searches the master scam database for a given input (URL or text).
 * @param {string} input The URL or text to search for.
 * @returns {Promise<{found: boolean, details: any[]}>} Search result.
 */
async function searchMasterData(input) {
  try {
    const db = initDb();
    return new Promise((resolve, reject) => {
      // Using FTS5 for efficient full-text search if available, otherwise LIKE
      db.get("PRAGMA table_info(scams_fts)", (err, row) => {
        const useFts = !err && row; // Check if FTS table exists
        let query;
        let params;

        if (useFts) {
          query = `SELECT url, source, type, date_added, region FROM scams_fts WHERE scams_fts MATCH ? LIMIT 1`;
          params = [`"${input}"`];
        } else {
          query = `SELECT url, source, type, date_added, region FROM scams WHERE url LIKE ? OR type LIKE ? LIMIT 1`;
          params = [`%${input}%`, `%${input}%`];
        }

        db.get(query, params, (err, row) => {
          db.close();
          if (err) {
            console.error("Database error, falling back to cache:", err.message);
            return resolve(searchFallbackCache(input));
          }
          if (row) {
            // Update fallback cache in background
            updateFallbackCache(row);
            resolve({
              found: true,
              details: [{
                url: row.url,
                source: row.source,
                type: row.type,
                date_added: row.date_added,
                region: row.region,
              }],
            });
          } else {
            resolve({ found: false, details: [] });
          }
        });
      });
    });
  } catch (error) {
    console.error("Initialization error, falling back to cache:", error.message);
    return searchFallbackCache(input);
  }
}

/**
 * Searches the local JSON fallback cache if the database is unavailable.
 */
function searchFallbackCache(input) {
  if (!fs.existsSync(FALLBACK_CACHE)) return { found: false, details: [] };
  try {
    const cache = JSON.parse(fs.readFileSync(FALLBACK_CACHE, "utf8"));
    const match = cache.find(item => item.url.includes(input) || item.type.includes(input));
    if (match) {
      return { found: true, details: [match], source: "fallback_cache" };
    }
  } catch (e) {
    console.error("Error reading fallback cache:", e.message);
  }
  return { found: false, details: [] };
}

/**
 * Updates the local JSON fallback cache with the latest results.
 */
function updateFallbackCache(data) {
  let cache = [];
  if (fs.existsSync(FALLBACK_CACHE)) {
    try {
      cache = JSON.parse(fs.readFileSync(FALLBACK_CACHE, "utf8"));
    } catch (e) {}
  }
  
  // Add new data if not already present
  if (!cache.some(item => item.url === data.url)) {
    cache.unshift(data);
    cache = cache.slice(0, 1000); // Keep only last 1000 entries
    try {
      fs.writeFileSync(FALLBACK_CACHE, JSON.stringify(cache, null, 2));
    } catch (e) {}
  }
}

module.exports = {
  searchMasterData,
  initDb,
  getBrands,
  addBrand
};
