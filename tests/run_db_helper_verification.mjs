// tests/run_db_helper_verification.mjs
// Verification suite for Loophole 19 & 20: Database Helper Hardening, Dynamic SQLite3 Fallback, and FTS5 Sanitization

import assert from 'node:assert/strict';
import { initDb, searchMasterData, searchFallbackCache, updateFallbackCache, getBrands } from '../lib/db_helper.js';

async function runTests() {
    console.log('--- Starting Database Helper Hardening Verification Tests ---');

    // 1. Safe Import & initDb Verification (Loophole 19)
    console.log('1. Testing initDb and dynamic package handling...');
    const db = initDb();
    // In serverless without sqlite3 installed, db is null; if installed, db is a Database instance. Either way, it must NOT crash.
    console.log(`   ✓ initDb executed safely without throwing (result: ${db ? 'database instance' : 'graceful null'})`);

    // 2. getBrands Verification
    console.log('2. Testing getBrands export...');
    const brands = await getBrands();
    assert.ok(Array.isArray(brands));
    assert.ok(brands.includes('SBI'));
    assert.ok(brands.includes('HDFC'));
    console.log(`   ✓ getBrands returns ${brands.length} monitored financial brands`);

    // 3. searchMasterData Null and Defensive Input Handling
    console.log('3. Testing searchMasterData defensive input validation...');
    const resEmpty = await searchMasterData('');
    assert.equal(resEmpty.found, false);
    assert.deepEqual(resEmpty.details, []);
    console.log('   ✓ Empty string returns clean empty result');

    const resNull = await searchMasterData(null);
    assert.equal(resNull.found, false);
    assert.deepEqual(resNull.details, []);
    console.log('   ✓ Null input returns clean empty result');

    const resUndefined = await searchMasterData(undefined);
    assert.equal(resUndefined.found, false);
    console.log('   ✓ Undefined input returns clean empty result');

    // 4. FTS5 Injection and Quote Sanitization (Loophole 20)
    console.log('4. Testing FTS5 quote injection handling...');
    const resQuotes = await searchMasterData('malicious" OR 1=1 --');
    assert.ok(resQuotes);
    assert.equal(typeof resQuotes.found, 'boolean');
    console.log('   ✓ Double quotes and SQL operators safely escaped without crashing');

    // 5. searchFallbackCache Null-Safety (Loophole 20)
    console.log('5. Testing searchFallbackCache defensive null-safety...');
    const cacheResNull = searchFallbackCache(null);
    assert.equal(cacheResNull.found, false);
    console.log('   ✓ searchFallbackCache handles null input safely');

    const cacheResEmpty = searchFallbackCache('');
    assert.equal(cacheResEmpty.found, false);
    console.log('   ✓ searchFallbackCache handles empty input safely');

    // 6. updateFallbackCache Robustness
    console.log('6. Testing updateFallbackCache robustness...');
    updateFallbackCache(null);
    updateFallbackCache({});
    updateFallbackCache({ dummy: true });
    console.log('   ✓ updateFallbackCache safely ignores invalid / null items without throwing');

    console.log('--- ALL DATABASE HELPER TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
