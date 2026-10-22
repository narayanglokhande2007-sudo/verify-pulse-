import path from "path";
import fs from "fs";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DB_FILE = path.join(__dirname, "../pipeline/daily-data/scams.db");
const FALLBACK_CACHE = path.join(__dirname, "../pipeline/daily-data/scam_cache.json");

// Safely attempt to load sqlite3 package without crashing serverless environments
let sqlite3 = null;
try {
  const sqlite3Package = require("sqlite3");
  sqlite3 = sqlite3Package.verbose();
} catch {
  // sqlite3 is not installed or not supported in this runtime environment (e.g. serverless read-only container)
  sqlite3 = null;
}

/**
 * Initializes the SQLite database and creates the 'scams' table if it doesn't exist.
 * This ensures the database is ready for use.
 */
export function initDb() {
  if (!sqlite3) {
    return null;
  }
  try {
    const db = new sqlite3.Database(DB_FILE, (err) => {
      if (err) {
        console.error("Error connecting to database:", err.message);
      } else {
        db.run(
          `CREATE TABLE IF NOT EXISTS scams (
            url TEXT PRIMARY KEY,
            source TEXT,
            type TEXT,
            date_added TEXT,
            region TEXT
          )`,
          (createErr) => {
            if (createErr) {
              console.error("Error creating scams table:", createErr.message);
            }
          }
        );
      }
    });
    return db;
  } catch (err) {
    console.error("Error initializing SQLite database:", err.message);
    return null;
  }
}

/**
 * Searches the master scam database for a given input (URL or text).
 * @param {string} input The URL or text to search for.
 * @returns {Promise<{found: boolean, details: any[]}>} Search result.
 */
export async function searchMasterData(input) {
  const safeInput = typeof input === 'string' ? input.trim() : (input ? String(input).trim() : '');
  if (!safeInput) {
    return { found: false, details: [] };
  }

  try {
    const db = initDb();
    if (!db) {
      return searchFallbackCache(safeInput);
    }

    return new Promise((resolve) => {
      // Using FTS5 for efficient full-text search if available, otherwise LIKE
      db.get("PRAGMA table_info(scams_fts)", (err, row) => {
        const useFts = !err && row; // Check if FTS table exists
        let query;
        let params;

        if (useFts) {
          // Loophole 20: Sanitize input for SQLite FTS5 query to avoid syntax error/injection
          const sanitizedFts = safeInput.replace(/"/g, '""');
          query = `SELECT url, source, type, date_added, region FROM scams_fts WHERE scams_fts MATCH ? LIMIT 1`;
          params = [`"${sanitizedFts}"`];
        } else {
          query = `SELECT url, source, type, date_added, region FROM scams WHERE url LIKE ? OR type LIKE ? LIMIT 1`;
          params = [`%${safeInput}%`, `%${safeInput}%`];
        }

        db.get(query, params, (dbErr, dbRow) => {
          try {
            db.close();
          } catch {}

          if (dbErr) {
            console.error("Database error, falling back to cache:", dbErr.message);
            return resolve(searchFallbackCache(safeInput));
          }
          if (dbRow) {
            // Update fallback cache in background
            updateFallbackCache(dbRow);
            resolve({
              found: true,
              details: [{
                url: dbRow.url,
                source: dbRow.source,
                type: dbRow.type,
                date_added: dbRow.date_added,
                region: dbRow.region,
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
    return searchFallbackCache(safeInput);
  }
}

/**
 * Searches the local JSON fallback cache if the database is unavailable.
 */
export function searchFallbackCache(input) {
  const safeInput = typeof input === 'string' ? input.trim().toLowerCase() : (input ? String(input).trim().toLowerCase() : '');
  if (!safeInput) return { found: false, details: [] };
  if (!fs.existsSync(FALLBACK_CACHE)) return { found: false, details: [] };

  try {
    const rawData = fs.readFileSync(FALLBACK_CACHE, "utf8");
    const cache = JSON.parse(rawData);
    if (!Array.isArray(cache)) return { found: false, details: [] };

    const match = cache.find(item => {
      if (!item || typeof item !== 'object') return false;
      const url = typeof item.url === 'string' ? item.url.toLowerCase() : '';
      const type = typeof item.type === 'string' ? item.type.toLowerCase() : '';
      return url.includes(safeInput) || type.includes(safeInput);
    });

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
export function updateFallbackCache(data) {
  if (!data || typeof data !== 'object' || !data.url) return;
  let cache = [];
  if (fs.existsSync(FALLBACK_CACHE)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(FALLBACK_CACHE, "utf8"));
      if (Array.isArray(parsed)) cache = parsed;
    } catch (e) {}
  }
  
  // Add new data if not already present
  if (!cache.some(item => item && item.url === data.url)) {
    cache.unshift(data);
    cache = cache.slice(0, 1000); // Keep only last 1000 entries
    try {
      fs.writeFileSync(FALLBACK_CACHE, JSON.stringify(cache, null, 2));
    } catch (e) {}
  }
}

/**
 * Returns a list of brands to monitor.
 * In a real scenario, this could be fetched from the database.
 */
export async function getBrands() {
  return ['SBI', 'HDFC', 'ICICI', 'Axis', 'Paytm', 'PhonePe', 'KBC', 'Airtel', 'Jio', 'Google', 'Microsoft', 'Apple'];
}

