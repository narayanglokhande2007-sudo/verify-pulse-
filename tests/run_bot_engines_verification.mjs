// tests/run_bot_engines_verification.mjs
// Verification suite for Telegram & WhatsApp Bot Engine hardening and AI model resilience

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import telegramHandler from '../api/telegram-bot.js';
import whatsappHandler from '../api/test.js';

function mockRes() {
    return {
        statusCode: null,
        body: null,
        headers: {},
        sentText: null,
        setHeader(name, val) { this.headers[name] = val; },
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return body; },
        send(text) { this.sentText = text; return text; }
    };
}

async function runTests() {
    console.log('--- Starting Bot Engines Hardening Verification Tests ---');

    // ==========================================
    // 1. Telegram Bot Verification Tests
    // ==========================================
    console.log('1. Testing Telegram Bot GET liveness check...');
    const tgGetRes = mockRes();
    await telegramHandler({ method: 'GET' }, tgGetRes);
    assert.equal(tgGetRes.statusCode, 200);
    assert.ok(tgGetRes.sentText.includes('running'));
    console.log('   ✓ Telegram GET returns 200 liveness check');

    console.log('2. Testing Telegram Bot HTTP method check...');
    const tgPutRes = mockRes();
    await telegramHandler({ method: 'PUT' }, tgPutRes);
    assert.equal(tgPutRes.statusCode, 405);
    console.log('   ✓ Telegram non-GET/POST rejected with 405');

    console.log('3. Testing Telegram Bot invalid JSON handling...');
    const tgJsonRes = mockRes();
    await telegramHandler({ method: 'POST', body: '{invalid-json' }, tgJsonRes);
    assert.equal(tgJsonRes.statusCode, 400);
    console.log('   ✓ Telegram invalid JSON safely returns 400');

    console.log('4. Testing Telegram Bot command routing (/start, /help, /score)...');
    const tgCmdRes = mockRes();
    await telegramHandler({
        method: 'POST',
        body: {
            message: {
                chat: { id: 12345 },
                text: '/start',
                from: { first_name: 'Tester' }
            }
        }
    }, tgCmdRes);
    assert.equal(tgCmdRes.statusCode, 200);
    assert.equal(tgCmdRes.sentText, 'ok');
    console.log('   ✓ Telegram /start handled safely with 200 ok');

    console.log('5. Testing Telegram Bot message scanning with resilient model fallback...');
    const tgScanRes = mockRes();
    await telegramHandler({
        method: 'POST',
        body: {
            message: {
                chat: { id: 12345 },
                text: 'Urgent: Your HDFC Bank account will be blocked today. Click https://fake-hdfc.com',
                from: { first_name: 'Tester' }
            }
        }
    }, tgScanRes);
    assert.equal(tgScanRes.statusCode, 200);
    assert.equal(tgScanRes.sentText, 'ok');
    console.log('   ✓ Telegram scam scan completed cleanly without unhandled exception (200 ok)');

    console.log('5b. Testing Telegram Webhook secret token enforcement...');
    process.env.TELEGRAM_WEBHOOK_SECRET = 'tg_super_secret_webhook_token_999';
    const tgNoAuthRes = mockRes();
    await telegramHandler({
        method: 'POST',
        headers: {},
        body: { message: { chat: { id: 12345 }, text: 'hello' } }
    }, tgNoAuthRes);
    assert.equal(tgNoAuthRes.statusCode, 401);
    assert.equal(tgNoAuthRes.body.error, 'UNAUTHORIZED_WEBHOOK');

    const tgWrongAuthRes = mockRes();
    await telegramHandler({
        method: 'POST',
        headers: { 'x-telegram-bot-api-secret-token': 'wrong-token' },
        body: { message: { chat: { id: 12345 }, text: 'hello' } }
    }, tgWrongAuthRes);
    assert.equal(tgWrongAuthRes.statusCode, 401);

    const tgValidAuthRes = mockRes();
    await telegramHandler({
        method: 'POST',
        headers: { 'x-telegram-bot-api-secret-token': 'tg_super_secret_webhook_token_999' },
        body: { message: { chat: { id: 12345 }, text: '/start' } }
    }, tgValidAuthRes);
    assert.equal(tgValidAuthRes.statusCode, 200);
    delete process.env.TELEGRAM_WEBHOOK_SECRET;
    console.log('   ✓ Telegram webhook secret token validation enforced safely (401 on missing/wrong, 200 on valid)');

    console.log('5c. Testing Telegram long input safety guard (> 4000 chars)...');
    const tgLongRes = mockRes();
    await telegramHandler({
        method: 'POST',
        body: {
            message: {
                chat: { id: 12345 },
                text: 'A'.repeat(4500)
            }
        }
    }, tgLongRes);
    assert.equal(tgLongRes.statusCode, 200);
    console.log('   ✓ Telegram over-long input safely guarded without crash (200 ok)');

    // ==========================================
    // 2. WhatsApp Bot Verification Tests (api/test.js)
    // ==========================================
    console.log('6. Testing WhatsApp Bot webhook verification handshake (GET)...');
    process.env.WHATSAPP_VERIFY_TOKEN = 'test_secret_token_123';
    const waVerifyRes = mockRes();
    await whatsappHandler({
        method: 'GET',
        query: {
            'hub.mode': 'subscribe',
            'hub.verify_token': 'test_secret_token_123',
            'hub.challenge': 'challenge_token_999'
        }
    }, waVerifyRes);
    assert.equal(waVerifyRes.statusCode, 200);
    assert.equal(waVerifyRes.sentText, 'challenge_token_999');
    console.log('   ✓ WhatsApp hub.challenge subscription handshake verified (200)');

    console.log('7. Testing WhatsApp Bot general GET liveness check...');
    const waLiveRes = mockRes();
    await whatsappHandler({
        method: 'GET',
        query: {}
    }, waLiveRes);
    assert.equal(waLiveRes.statusCode, 200);
    assert.ok(waLiveRes.sentText.includes('WhatsApp route alive'));
    console.log('   ✓ WhatsApp route alive liveness verified (200)');

    console.log('8. Testing WhatsApp Bot command routing (/help)...');
    const waHelpRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        body: {
            entry: [{
                changes: [{
                    value: {
                        messages: [{
                            from: '919876543210',
                            type: 'text',
                            text: { body: '/help' }
                        }]
                    }
                }]
            }]
        }
    }, waHelpRes);
    assert.equal(waHelpRes.statusCode, 200);
    assert.equal(waHelpRes.sentText, 'ok');
    console.log('   ✓ WhatsApp /help command dispatched cleanly (200 ok)');

    console.log('9. Testing WhatsApp Bot message scanning with resilient model fallback...');
    const waScanRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        body: {
            entry: [{
                changes: [{
                    value: {
                        messages: [{
                            from: '919876543210',
                            type: 'text',
                            text: { body: 'Lottery win: Send ₹500 processing fee to win@upi' }
                        }]
                    }
                }]
            }]
        }
    }, waScanRes);
    assert.equal(waScanRes.statusCode, 200);
    assert.equal(waScanRes.sentText, 'ok');
    console.log('   ✓ WhatsApp scan completed cleanly without unhandled exception (200 ok)');

    console.log('10. Testing WhatsApp Meta webhook signature enforcement...');
    const metaSecret = 'test_meta_app_secret_888';
    process.env.WHATSAPP_APP_SECRET = metaSecret;
    const samplePayload = JSON.stringify({
        entry: [{ changes: [{ value: { messages: [{ from: '919876543210', type: 'text', text: { body: '/help' } }] } }] }]
    });

    // 10a: Missing signature
    const waNoSigRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        headers: {},
        body: samplePayload
    }, waNoSigRes);
    assert.equal(waNoSigRes.statusCode, 401);
    assert.equal(waNoSigRes.body.error, 'UNAUTHORIZED_WEBHOOK');

    // 10b: Invalid signature
    const waBadSigRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        headers: { 'x-hub-signature-256': 'sha256=bad0000000000000000000000000000000000000000000000000000000000000' },
        body: samplePayload
    }, waBadSigRes);
    assert.equal(waBadSigRes.statusCode, 401);

    // 10c: Valid HMAC-SHA256 signature
    const validHmac = crypto.createHmac('sha256', metaSecret).update(samplePayload).digest('hex');
    const waGoodSigRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        headers: { 'x-hub-signature-256': `sha256=${validHmac}` },
        body: samplePayload
    }, waGoodSigRes);
    assert.equal(waGoodSigRes.statusCode, 200);
    delete process.env.WHATSAPP_APP_SECRET;
    console.log('   ✓ WhatsApp Meta webhook signature validation enforced cleanly (401 on invalid, 200 on valid)');

    console.log('11. Testing WhatsApp invalid sender phone number guard...');
    const waBadPhoneRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        body: {
            entry: [{ changes: [{ value: { messages: [{ from: 'invalid_phone_attacker', type: 'text', text: { body: 'hello' } }] } }] }]
        }
    }, waBadPhoneRes);
    assert.equal(waBadPhoneRes.statusCode, 200);
    assert.equal(waBadPhoneRes.sentText, 'ok');
    console.log('   ✓ WhatsApp invalid sender phone number safely ignored without processing (200 ok)');

    console.log('12. Testing WhatsApp over-long input safety guard (> 4000 chars)...');
    const waLongRes = mockRes();
    await whatsappHandler({
        method: 'POST',
        body: {
            entry: [{ changes: [{ value: { messages: [{ from: '919876543210', type: 'text', text: { body: 'W'.repeat(4500) } }] } }] }]
        }
    }, waLongRes);
    assert.equal(waLongRes.statusCode, 200);
    console.log('   ✓ WhatsApp over-long input safely guarded without crash (200 ok)');

    console.log('--- ALL BOT ENGINE TESTS PASSED SUCCESSFULLY ---');
}

runTests().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
});
