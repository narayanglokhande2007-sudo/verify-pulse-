/**
 * VerifyPulse Brand Protection API
 * ================================
 * Enterprise API for banks to access brand protection data and alerts.
 * Provides real-time monitoring, threat intelligence, and automated reporting.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const BRAND_PROTECTION_DB = path.join(__dirname, '../pipeline/daily-data/brand_protection.db');

// ============================================================================
// DATABASE HELPER
// ============================================================================

function getDB() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(BRAND_PROTECTION_DB, (err) => {
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
// ENDPOINT: GET /api/brand-protection/threats
// ============================================================================
/**
 * Retrieve all active brand threats for a specific bank.
 * Query Parameters:
 *   - bank_id: (required) Bank identifier (e.g., 'sbi', 'hdfc')
 *   - status: (optional) Filter by status ('detected', 'investigating', 'resolved')
 *   - limit: (optional) Max results (default: 50)
 *   - offset: (optional) Pagination offset (default: 0)
 */
async function getBrandThreats(req, res) {
    try {
        const { bank_id, status = 'detected', limit = 50, offset = 0 } = req.query;

        if (!bank_id) {
            return res.status(400).json({
                error: 'Missing required parameter: bank_id',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();

        let query = `
            SELECT 
                id, domain, bank_brand, detection_date, status, confidence_score,
                visual_match, behavioral_risk, ip_address, hosting_provider,
                alert_sent, takedown_requested
            FROM brand_threats
            WHERE bank_brand = ?
        `;
        let params = [bank_id];

        if (status) {
            query += ` AND status = ?`;
            params.push(status);
        }

        query += ` ORDER BY detection_date DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), parseInt(offset));

        const threats = await runQuery(db, query, params);

        // Get total count
        let countQuery = `SELECT COUNT(*) as total FROM brand_threats WHERE bank_brand = ?`;
        let countParams = [bank_id];
        if (status) {
            countQuery += ` AND status = ?`;
            countParams.push(status);
        }

        const countResult = await runQuery(db, countQuery, countParams);
        const total = countResult[0].total;

        db.close();

        return res.status(200).json({
            success: true,
            data: {
                threats: threats.map(t => ({
                    id: t.id,
                    domain: t.domain,
                    bank_brand: t.bank_brand,
                    detected_at: t.detection_date,
                    status: t.status,
                    confidence: `${(t.confidence_score * 100).toFixed(2)}%`,
                    visual_imitation: t.visual_match === 1,
                    behavioral_risk: t.behavioral_risk,
                    infrastructure: {
                        ip: t.ip_address,
                        hosting: t.hosting_provider
                    },
                    alert_sent: t.alert_sent === 1,
                    takedown_requested: t.takedown_requested === 1
                })),
                pagination: {
                    total,
                    limit: parseInt(limit),
                    offset: parseInt(offset),
                    has_more: (parseInt(offset) + parseInt(limit)) < total
                }
            }
        });

    } catch (error) {
        console.error('Error fetching brand threats:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR',
            message: error.message
        });
    }
}

// ============================================================================
// ENDPOINT: GET /api/brand-protection/dashboard
// ============================================================================
/**
 * Get comprehensive brand protection dashboard for a bank.
 * Includes statistics, recent threats, and actionable insights.
 */
async function getBrandDashboard(req, res) {
    try {
        const { bank_id } = req.query;

        if (!bank_id) {
            return res.status(400).json({
                error: 'Missing required parameter: bank_id',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();

        // Get statistics
        const stats = await runQuery(db, `
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN status = 'detected' THEN 1 ELSE 0 END) as active_threats,
                SUM(CASE WHEN takedown_requested = 1 THEN 1 ELSE 0 END) as takedowns_initiated,
                AVG(confidence_score) as avg_confidence,
                SUM(CASE WHEN visual_match = 1 THEN 1 ELSE 0 END) as visual_matches
            FROM brand_threats
            WHERE bank_brand = ?
        `, [bank_id]);

        // Get threats by severity
        const severityBreakdown = await runQuery(db, `
            SELECT 
                CASE 
                    WHEN confidence_score > 0.8 THEN 'CRITICAL'
                    WHEN confidence_score > 0.6 THEN 'HIGH'
                    ELSE 'MEDIUM'
                END as severity,
                COUNT(*) as count
            FROM brand_threats
            WHERE bank_brand = ? AND status = 'detected'
            GROUP BY severity
        `, [bank_id]);

        // Get recent threats (last 7 days)
        const recentThreats = await runQuery(db, `
            SELECT 
                id, domain, detection_date, confidence_score, 
                visual_match, behavioral_risk, ip_address
            FROM brand_threats
            WHERE bank_brand = ? AND status = 'detected'
            AND detection_date >= datetime('now', '-7 days')
            ORDER BY detection_date DESC
            LIMIT 10
        `, [bank_id]);

        // Get alert history
        const alertHistory = await runQuery(db, `
            SELECT 
                alert_timestamp, COUNT(*) as alerts_sent
            FROM alert_history
            WHERE bank_id = ?
            GROUP BY DATE(alert_timestamp)
            ORDER BY alert_timestamp DESC
            LIMIT 30
        `, [bank_id]);

        db.close();

        return res.status(200).json({
            success: true,
            data: {
                bank_id,
                timestamp: new Date().toISOString(),
                statistics: {
                    total_threats: stats[0].total_threats || 0,
                    active_threats: stats[0].active_threats || 0,
                    takedowns_initiated: stats[0].takedowns_initiated || 0,
                    average_confidence: `${((stats[0].avg_confidence || 0) * 100).toFixed(2)}%`,
                    visual_imitations_detected: stats[0].visual_matches || 0
                },
                severity_breakdown: Object.fromEntries(
                    severityBreakdown.map(s => [s.severity, s.count])
                ),
                recent_threats: recentThreats.map(t => ({
                    id: t.id,
                    domain: t.domain,
                    detected: t.detection_date,
                    confidence: `${(t.confidence_score * 100).toFixed(2)}%`,
                    visual_imitation: t.visual_match === 1,
                    risk_type: t.behavioral_risk,
                    ip: t.ip_address
                })),
                alert_activity: alertHistory.map(a => ({
                    date: a.alert_timestamp,
                    alerts_sent: a.alerts_sent
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
// ENDPOINT: POST /api/brand-protection/report-threat
// ============================================================================
/**
 * Allow banks to manually report suspected threats.
 * Integrates with the automated detection system.
 */
async function reportThreat(req, res) {
    try {
        const { bank_id, domain, description } = req.body;

        if (!bank_id || !domain) {
            return res.status(400).json({
                error: 'Missing required fields: bank_id, domain',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();

        // Check if threat already exists
        const existing = await runQuery(db, 
            'SELECT id FROM brand_threats WHERE domain = ?', 
            [domain]
        );

        if (existing.length > 0) {
            db.close();
            return res.status(409).json({
                error: 'Threat already reported',
                code: 'DUPLICATE_THREAT',
                threat_id: existing[0].id
            });
        }

        // Insert new threat
        db.run(`
            INSERT INTO brand_threats 
            (domain, bank_brand, detection_date, status, confidence_score, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [domain, bank_id, new Date().toISOString(), 'investigating', 0.7, description],
        function(err) {
            if (err) {
                db.close();
                return res.status(500).json({
                    error: 'Failed to report threat',
                    code: 'INSERT_ERROR'
                });
            }

            db.close();
            return res.status(201).json({
                success: true,
                message: 'Threat reported successfully',
                threat_id: this.lastID
            });
        });

    } catch (error) {
        console.error('Error reporting threat:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: POST /api/brand-protection/request-takedown
// ============================================================================
/**
 * Request immediate takedown action for a detected threat.
 */
async function requestTakedown(req, res) {
    try {
        const { threat_id, bank_id, reason } = req.body;

        if (!threat_id || !bank_id) {
            return res.status(400).json({
                error: 'Missing required fields: threat_id, bank_id',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();

        // Update threat status
        db.run(`
            UPDATE brand_threats 
            SET takedown_requested = 1, takedown_timestamp = ?, status = 'investigating'
            WHERE id = ? AND bank_brand = ?
        `, [new Date().toISOString(), threat_id, bank_id],
        function(err) {
            if (err) {
                db.close();
                return res.status(500).json({
                    error: 'Failed to request takedown',
                    code: 'UPDATE_ERROR'
                });
            }

            if (this.changes === 0) {
                db.close();
                return res.status(404).json({
                    error: 'Threat not found',
                    code: 'NOT_FOUND'
                });
            }

            // Log the takedown request
            db.run(`
                INSERT INTO alert_history 
                (threat_id, bank_id, alert_type, alert_timestamp, status)
                VALUES (?, ?, ?, ?, ?)
            `, [threat_id, bank_id, 'takedown_request', new Date().toISOString(), 'initiated']);

            db.close();
            return res.status(200).json({
                success: true,
                message: 'Takedown request initiated',
                threat_id,
                status: 'investigating'
            });
        });

    } catch (error) {
        console.error('Error requesting takedown:', error);
        return res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
}

// ============================================================================
// ENDPOINT: GET /api/brand-protection/export-report
// ============================================================================
/**
 * Export comprehensive brand protection report in JSON or CSV format.
 */
async function exportReport(req, res) {
    try {
        const { bank_id, format = 'json', days = 30 } = req.query;

        if (!bank_id) {
            return res.status(400).json({
                error: 'Missing required parameter: bank_id',
                code: 'INVALID_REQUEST'
            });
        }

        const db = await getDB();

        const threats = await runQuery(db, `
            SELECT * FROM brand_threats
            WHERE bank_brand = ? AND detection_date >= datetime('now', ? || ' days')
            ORDER BY detection_date DESC
        `, [bank_id, `-${days}`]);

        db.close();

        if (format === 'csv') {
            // Convert to CSV
            const csv = [
                'Domain,Bank,Detected,Status,Confidence,Visual Match,Behavioral Risk,IP,Hosting,Alert Sent,Takedown Requested',
                ...threats.map(t => 
                    `"${t.domain}","${t.bank_brand}","${t.detection_date}","${t.status}","${(t.confidence_score * 100).toFixed(2)}%","${t.visual_match}","${t.behavioral_risk}","${t.ip_address}","${t.hosting_provider}","${t.alert_sent}","${t.takedown_requested}"`
                )
            ].join('\n');

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="brand-protection-${bank_id}-${new Date().toISOString().split('T')[0]}.csv"`);
            return res.send(csv);
        }

        // Default JSON format
        return res.status(200).json({
            success: true,
            data: {
                bank_id,
                report_period_days: parseInt(days),
                generated_at: new Date().toISOString(),
                total_threats: threats.length,
                threats: threats.map(t => ({
                    domain: t.domain,
                    bank_brand: t.bank_brand,
                    detected_at: t.detection_date,
                    status: t.status,
                    confidence: `${(t.confidence_score * 100).toFixed(2)}%`,
                    visual_imitation: t.visual_match === 1,
                    behavioral_risk: t.behavioral_risk,
                    infrastructure: {
                        ip: t.ip_address,
                        hosting: t.hosting_provider
                    },
                    alert_sent: t.alert_sent === 1,
                    takedown_requested: t.takedown_requested === 1
                }))
            }
        });

    } catch (error) {
        console.error('Error exporting report:', error);
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
    getBrandThreats,
    getBrandDashboard,
    reportThreat,
    requestTakedown,
    exportReport
};
