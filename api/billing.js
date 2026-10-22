// api/billing.js
// VerifyPulse Unified Billing, Orders & Webhook Gateway
import handleCreateOrder from '../lib/billing_order.js';
import handleWebhook from '../lib/billing_webhook.js';

export default async function handler(req, res) {
    const action = req.query?.action;
    const isWebhook = action === 'webhook' || Boolean(req.headers?.['x-razorpay-signature']);

    if (isWebhook) {
        return handleWebhook(req, res);
    }
    return handleCreateOrder(req, res);
}
