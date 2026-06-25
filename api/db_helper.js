// api/db_helper.js
// Minimal stub for scam database lookup.
// The full scam data lives in pipeline/daily-data/ (scams.db is gitignored,
// JSONL files are too large for Vercel function bundle).
// This stub returns "not found" so other layers (ghost agent, AI) can take over.
// Safe to extend later when a hosted DB is available.

function searchMasterData(input) {
    if (!input || typeof input !== 'string') {
        return { found: false };
    }
    // Placeholder: real DB lookup will be wired in later.
    return { found: false };
}

module.exports = { searchMasterData };
