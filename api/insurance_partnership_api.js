/**
 * VerifyPulse Insurance Partnership API
 * ====================================
 * Manages insurance partnerships, referrals, revenue sharing, and customer onboarding.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const INSURANCE_DB = path.join(__dirname, '../pipeline/daily-data/insurance_partnerships.db');

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

function initInsuranceDB() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(INSURANCE_DB, (err) => {
            if (err) reject(err);
            else {
                db.serialize(() => {
                    // Insurance Partners Table
                    db.run(`CREATE TABLE IF NOT EXISTS insurance_partners (
                        id TEXT PRIMARY KEY,
                        company_name TEXT NOT NULL,
                        contact_email TEXT NOT NULL,
                        contact_name TEXT NOT NULL,
                        phone TEXT,
                        company_type TEXT,
                        tier TEXT DEFAULT 'Starter',
                        policyholders_count INTEGER DEFAULT 0,
                        revenue_share_percentage REAL DEFAULT 15.0,
                        api_key TEXT UNIQUE,
                        status TEXT DEFAULT 'pending',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        notes TEXT
                    )`);

                    // Referred Customers Table
                    db.run(`CREATE TABLE IF NOT EXISTS referred_customers (
                        id TEXT PRIMARY KEY,
                        partner_id TEXT NOT NULL,
                        customer_email TEXT NOT NULL,
                        customer_name TEXT NOT NULL,
                        subscription_tier TEXT,
                        monthly_fee REAL DEFAULT 99.0,
                        status TEXT DEFAULT 'active',
                        referred_at TEXT NOT NULL,
                        activated_at TEXT,
                        FOREIGN KEY(partner_id) REFERENCES insurance_partners(id)
                    )`);

                    // Revenue Tracking Table
                    db.run(`CREATE TABLE IF NOT EXISTS revenue_tracking (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        partner_id TEXT NOT NULL,
                        month TEXT NOT NULL,
                        total_customers INTEGER,
                        total_revenue REAL,
                        partner_share REAL,
                        status TEXT DEFAULT 'pending',
                        paid_at TEXT,
                        FOREIGN KEY(partner_id) REFERENCES insurance_partners(id)
                    )`);

                    // Partnership Inquiries Table
                    db.run(`CREATE TABLE IF NOT EXISTS partnership_inquiries (
                        id TEXT PRIMARY KEY,
                        company_name TEXT NOT NULL,
                        contact_email TEXT NOT NULL,
                        contact_name TEXT NOT NULL,
                        company_type TEXT,
                        policyholders_range TEXT,
                        message TEXT,
                        status TEXT DEFAULT 'new',
                        submitted_at TEXT NOT NULL,
                        responded_at TEXT
                    )`);

                    // Indices
                    db.run('CREATE INDEX IF NOT EXISTS idx_partner_status ON insurance_partners(status)');
                    db.run('CREATE INDEX IF NOT EXISTS idx_customer_partner ON referred_customers(partner_id)');
                    db.run('CREATE INDEX IF NOT EXISTS idx_revenue_partner ON revenue_tracking(partner_id)');
                });
                resolve(db);
            }
        });
    });
}

function getDB() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(INSURANCE_DB, (err) => {
            if (err) reject(err);
            else resolve(db);
        });
    });
}

function runQuery(db, query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// ============================================================================
// ENDPOINT: POST /api/insurance/inquiry
// ============================================================================
/**
 * Submit a partnership inquiry from the cyber-insurance.html form.
 */
async function submitInquiry(req, res) {
    try {
        const { company_name, contact_email, contact_name, phone, company_type, policyholders_range, message } = req.body;

        if (!company_name || !contact_email || !contact_name || !message) {
            return res.status(400).json({
                error: 'Missing required fields',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();
        const inquiry_id = `INQ-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        db.run(`
            INSERT INTO partnership_inquiries 
            (id, company_name, contact_email, contact_name, company_type, policyholders_range, message, submitted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [inquiry_id, company_name, contact_email, contact_name, company_type, policyholders_range, message, new Date().toISOString()],
        function(err) {
            db.close();
            if (err) {
                return res.status(500).json({
                    error: 'Failed to submit inquiry',
                    code: 'INSERT_ERROR'
                });
            }

            return res.status(201).json({
                success: true,
                message: 'Inquiry submitted successfully',
                inquiry_id,
                next_steps: 'Our team will review your inquiry and contact you within 24 hours.'
            });
        });

    } catch (error) {
        console.error('Error submitting inquiry:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: POST /api/insurance/partner/register
// ============================================================================
/**
 * Register an approved insurance partner (admin only).
 */
async function registerPartner(req, res) {
    try {
        const { company_name, contact_email, contact_name, phone, company_type, tier, policyholders_count } = req.body;

        if (!company_name || !contact_email) {
            return res.status(400).json({
                error: 'Missing required fields',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();
        const partner_id = `PARTNER-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const api_key = crypto.randomBytes(32).toString('hex');
        
        // Determine revenue share based on tier
        let revenue_share = 15.0;
        if (tier === 'Growth') revenue_share = 20.0;
        if (tier === 'Enterprise') revenue_share = 25.0;

        db.run(`
            INSERT INTO insurance_partners 
            (id, company_name, contact_email, contact_name, phone, company_type, tier, policyholders_count, revenue_share_percentage, api_key, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [partner_id, company_name, contact_email, contact_name, phone, company_type, tier || 'Starter', policyholders_count || 0, revenue_share, api_key, 'active', new Date().toISOString(), new Date().toISOString()],
        function(err) {
            db.close();
            if (err) {
                return res.status(500).json({
                    error: 'Failed to register partner',
                    code: 'INSERT_ERROR'
                });
            }

            return res.status(201).json({
                success: true,
                message: 'Partner registered successfully',
                partner: {
                    id: partner_id,
                    company_name,
                    api_key,
                    tier: tier || 'Starter',
                    revenue_share_percentage: revenue_share
                }
            });
        });

    } catch (error) {
        console.error('Error registering partner:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: GET /api/insurance/partner/:partner_id/dashboard
// ============================================================================
/**
 * Get partner dashboard with referral stats and revenue information.
 */
async function getPartnerDashboard(req, res) {
    try {
        const { partner_id } = req.params;

        const db = await getDB();

        // Get partner info
        const partners = await runQuery(db, 'SELECT * FROM insurance_partners WHERE id = ?', [partner_id]);
        if (partners.length === 0) {
            db.close();
            return res.status(404).json({
                error: 'Partner not found',
                code: 'NOT_FOUND'
            });
        }

        const partner = partners[0];

        // Get active customers
        const customers = await runQuery(db, 
            'SELECT COUNT(*) as count FROM referred_customers WHERE partner_id = ? AND status = "active"', 
            [partner_id]
        );

        // Get monthly revenue
        const revenue = await runQuery(db,
            'SELECT * FROM revenue_tracking WHERE partner_id = ? ORDER BY month DESC LIMIT 12',
            [partner_id]
        );

        // Get recent referrals
        const recent = await runQuery(db,
            'SELECT * FROM referred_customers WHERE partner_id = ? ORDER BY referred_at DESC LIMIT 10',
            [partner_id]
        );

        db.close();

        return res.status(200).json({
            success: true,
            data: {
                partner: {
                    id: partner.id,
                    company_name: partner.company_name,
                    tier: partner.tier,
                    status: partner.status,
                    revenue_share_percentage: partner.revenue_share_percentage
                },
                statistics: {
                    active_customers: customers[0].count,
                    total_policyholders: partner.policyholders_count,
                    monthly_revenue: revenue.length > 0 ? revenue[0].total_revenue : 0,
                    partner_monthly_share: revenue.length > 0 ? revenue[0].partner_share : 0
                },
                revenue_history: revenue.map(r => ({
                    month: r.month,
                    total_revenue: r.total_revenue,
                    partner_share: r.partner_share,
                    status: r.status,
                    paid_at: r.paid_at
                })),
                recent_referrals: recent.map(c => ({
                    customer_email: c.customer_email,
                    customer_name: c.customer_name,
                    referred_at: c.referred_at,
                    status: c.status
                }))
            }
        });

    } catch (error) {
        console.error('Error fetching dashboard:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: POST /api/insurance/partner/:partner_id/refer-customer
// ============================================================================
/**
 * Refer a new customer through the partner program.
 */
async function referCustomer(req, res) {
    try {
        const { partner_id } = req.params;
        const { customer_email, customer_name, subscription_tier } = req.body;

        if (!customer_email || !customer_name) {
            return res.status(400).json({
                error: 'Missing required fields',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();

        // Verify partner exists
        const partners = await runQuery(db, 'SELECT id FROM insurance_partners WHERE id = ?', [partner_id]);
        if (partners.length === 0) {
            db.close();
            return res.status(404).json({
                error: 'Partner not found',
                code: 'NOT_FOUND'
            });
        }

        const customer_id = `CUST-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        db.run(`
            INSERT INTO referred_customers 
            (id, partner_id, customer_email, customer_name, subscription_tier, referred_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [customer_id, partner_id, customer_email, customer_name, subscription_tier || 'Growth', new Date().toISOString()],
        function(err) {
            db.close();
            if (err) {
                return res.status(500).json({
                    error: 'Failed to refer customer',
                    code: 'INSERT_ERROR'
                });
            }

            return res.status(201).json({
                success: true,
                message: 'Customer referred successfully',
                customer: {
                    id: customer_id,
                    email: customer_email,
                    name: customer_name,
                    status: 'pending_activation'
                }
            });
        });

    } catch (error) {
        console.error('Error referring customer:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: GET /api/insurance/partner/:partner_id/inquiries
// ============================================================================
/**
 * Get all partnership inquiries (admin endpoint).
 */
async function getInquiries(req, res) {
    try {
        const db = await getDB();

        const inquiries = await runQuery(db, 
            'SELECT * FROM partnership_inquiries ORDER BY submitted_at DESC'
        );

        db.close();

        return res.status(200).json({
            success: true,
            data: {
                inquiries: inquiries.map(i => ({
                    id: i.id,
                    company_name: i.company_name,
                    contact_email: i.contact_email,
                    contact_name: i.contact_name,
                    company_type: i.company_type,
                    policyholders_range: i.policyholders_range,
                    status: i.status,
                    submitted_at: i.submitted_at,
                    responded_at: i.responded_at
                }))
            }
        });

    } catch (error) {
        console.error('Error fetching inquiries:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: POST /api/insurance/admin/calculate-revenue
// ============================================================================
/**
 * Calculate and record monthly revenue for all partners (admin/scheduled task).
 */
async function calculateMonthlyRevenue(req, res) {
    try {
        const db = await getDB();
        const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM

        // Get all active partners
        const partners = await runQuery(db, 'SELECT id, revenue_share_percentage FROM insurance_partners WHERE status = "active"');

        for (const partner of partners) {
            // Get active customer count
            const customers = await runQuery(db,
                'SELECT COUNT(*) as count FROM referred_customers WHERE partner_id = ? AND status = "active"',
                [partner.id]
            );

            const customer_count = customers[0].count;
            const monthly_fee = 99.0; // Standard monthly fee
            const total_revenue = customer_count * monthly_fee;
            const partner_share = total_revenue * (partner.revenue_share_percentage / 100);

            // Insert revenue record
            db.run(`
                INSERT OR REPLACE INTO revenue_tracking 
                (partner_id, month, total_customers, total_revenue, partner_share, status)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [partner.id, currentMonth, customer_count, total_revenue, partner_share, 'pending']);
        }

        db.close();

        return res.status(200).json({
            success: true,
            message: 'Monthly revenue calculated for all partners',
            month: currentMonth
        });

    } catch (error) {
        console.error('Error calculating revenue:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// EXPORT HANDLERS
// ============================================================================

module.exports = {
    initInsuranceDB,
    submitInquiry,
    registerPartner,
    getPartnerDashboard,
    referCustomer,
    getInquiries,
    calculateMonthlyRevenue
};
