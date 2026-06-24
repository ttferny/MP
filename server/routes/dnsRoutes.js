/**
 * ============================================================
 * dnsRoutes.js — Automated DNS & DKIM Checking Routes
 * ============================================================
 * 
 * Endpoints for automated domain checking
 */

const express = require('express');
const router = express.Router();

const { 
  autoDnsCheck, 
  autoDkimValidation, 
  autoFullCheck 
} = require('../services/autoDnsChecker');
const logger = require('../utils/logger');

/**
 * POST /api/dns/check
 * Automatically check DNS records for a domain
 */
router.post('/check', async (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'domain (string) is required' });
    }

    const results = await autoDnsCheck(domain);
    
    return res.status(200).json({
      success: true,
      data: results,
    });
  } catch (err) {
    logger.error(`DNS check error: ${err.message}`);
    return res.status(400).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/dns/dkim-validate
 * Auto-validate DKIM from raw email header
 */
router.post('/dkim-validate', async (req, res) => {
  try {
    const { rawHeader } = req.body;

    if (!rawHeader || typeof rawHeader !== 'string') {
      return res.status(400).json({ error: 'rawHeader (string) is required' });
    }

    const results = await autoDkimValidation(rawHeader);
    
    return res.status(200).json({
      success: true,
      data: results,
    });
  } catch (err) {
    logger.error(`DKIM validation error: ${err.message}`);
    return res.status(400).json({
      success: false,
      error: err.message,
    });
  }
});

/**
 * POST /api/dns/full-check
 * Complete auto-check: DNS records + optional header validation
 */
router.post('/full-check', async (req, res) => {
  try {
    const { domain, rawHeader } = req.body;

    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'domain (string) is required' });
    }

    const results = await autoFullCheck(domain, rawHeader);
    
    return res.status(200).json({
      success: true,
      data: results,
    });
  } catch (err) {
    logger.error(`Full check error: ${err.message}`);
    return res.status(400).json({
      success: false,
      error: err.message,
    });
  }
});

module.exports = router;
