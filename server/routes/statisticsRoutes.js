// server/routes/statisticsRoutes.js
const express = require('express');
const router = express.Router();
const rawStore = require('../utils/store');

router.get('/summary', (req, res) => {
    try {
        // Diagnostic check: log to terminal what store actually is
        console.log("Store loaded type:", typeof rawStore, "Is Array?:", Array.isArray(rawStore));

        // Safely extract or default to an array regardless of import style
        let scanHistory = [];
        if (Array.isArray(rawStore)) {
            scanHistory = rawStore;
        } else if (rawStore && Array.isArray(rawStore.scanHistory)) {
            scanHistory = rawStore.scanHistory;
        }

        const stats = {
            totalAnalyzed: scanHistory.length,
            authentication: {
                spfPass: 0, spfFail: 0,
                dkimPass: 0, dkimFail: 0,
                dmarcPass: 0, dmarcFail: 0,
            },
            aiClassifications: {
                safe: 0, phishing: 0, spoofing: 0, spam: 0
            },
            averageRiskScore: 0
        };

        let totalRisk = 0;

        // Loop safely through scan history
        scanHistory.forEach(record => {
            if (record.spf === 'pass') stats.authentication.spfPass++;
            else stats.authentication.spfFail++;
            
            if (record.dkim === 'pass') stats.authentication.dkimPass++;
            else stats.authentication.dkimFail++;
            
            if (record.dmarc === 'pass') stats.authentication.dmarcPass++;
            else stats.authentication.dmarcFail++;

            if (stats.aiClassifications[record.aiThreat] !== undefined) {
                stats.aiClassifications[record.aiThreat]++;
            }

            totalRisk += (record.riskScore || 0);
        });

        stats.averageRiskScore = scanHistory.length > 0 
            ? (totalRisk / scanHistory.length).toFixed(1) 
            : 0;

        res.status(200).json({ success: true, data: stats });

    } catch (error) {
        console.error("Dashboard Math Error:", error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to aggregate statistics',
            details: error.message 
        });
    }
});

module.exports = router;