/**
 * ============================================================
 * app.js — Express Server Entry Point
 * ============================================================
 *
 * WHAT THIS FILE DOES (simple version for pitching):
 * ---------------------------------------------------
 * This is the "front door" of our backend.
 * It starts the web server, sets up the routes (URLs the frontend
 * can call), and connects all parts of the project together.
 *
 * FLOW OVERVIEW:
 * --------------
 *  Browser/Frontend (index.html)
 *       ↓  sends HTTP POST request
 *  app.js  (receives request, routes it)
 *       ↓
 *  routes/analyse.js  (decides which service to call)
 *       ↓
 *  services/parser.js → spf.js → dkim.js → dmarc.js
 *       ↓
 *  JSON result sent back to frontend for display
 */

require('dotenv').config(); // must be first line — loads .env before any other module
const express = require('express');
const cors = require('cors');
const path = require('path');
const logger = require('./utils/logger');

// Import route files — each file handles a group of related API endpoints
const analyseRoutes = require('./routes/analyse');   // Main pipeline: parse+SPF+DKIM+DMARC
const dmarcRoutes   = require('./routes/dmarcRoutes'); // Zircon's DMARC-specific routes
const spfRoutes     = require('./routes/spfRoutes');   // SPF POC routes
const dnsRoutes     = require('./routes/dnsRoutes');   // Automated DNS/DKIM checking
const dnsManagementRoutes = require('./routes/dnsManagementRoutes'); // DNS record management (add, update, delete)
const { startSMTPServer } = require('./services/smtpReceiver');
const statisticsRoutes = require('./routes/statisticsRoutes'); // <-- ADD THIS LINE HERE

const app = express();
const PORT = process.env.PORT || 3000;
let server;

// ── Middleware ────────────────────────────────
// cors()           — allows the frontend (different port) to call this backend
// express.json()   — lets us read JSON from POST request bodies
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Static Files ──────────────────────────────
// Serve the HTML/CSS/JS frontend files from their matching client subfolders
const clientRoot = path.join(__dirname, '../client');
const htmlRoot = path.join(clientRoot, 'html');
const cssRoot = path.join(clientRoot, 'css');
const jsRoot = path.join(clientRoot, 'js');

app.use(express.static(htmlRoot));          // serves /index.html, /spf.html, etc.
app.use('/html', express.static(htmlRoot)); // allows /html/index.html and /html/spf.html
app.use('/css', express.static(cssRoot));   // serves /css/*.css
app.use('/js', express.static(jsRoot));     // serves /js/*.js

const smtp = startSMTPServer(); // Start the SMTP server to receive test emails (Zircon)

// ── API Routes ────────────────────────────────
// All API calls are prefixed with /api/ to separate them from page URLs
app.use('/api/analyse', analyseRoutes);  // POST /api/analyse/header  → full email check
                                          // POST /api/analyse/domain  → DNS record lookup
                                          // POST /api/analyse/scenario → run demo scenario
app.use('/api/dmarc',   dmarcRoutes);    // DMARC-specific routes (Zircon)
app.use('/api/spf',     spfRoutes);      // SPF POC routes
app.use('/api/dns',     dnsRoutes);      // Automated DNS/DKIM checking
app.use('/api/dns-mgmt', dnsManagementRoutes); // DNS record management (add, update, delete, bulk operations)
app.use('/api/statistics', statisticsRoutes);
app.get('/api/dmarc/smtp/latest', (req, res) => {
  const result = smtp.getLastResult();
  res.json(result || { status: 'waiting', message: 'No emails received yet' });
});

app.delete('/api/dmarc/smtp/latest', (req, res) => {
  smtp.clearLastResult();
  res.json({ message: 'Cleared' });
});

// ── Health Check ──────────────────────────────
// Simple endpoint to confirm the server is running
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Fallback ──────────────────────────────────
// For any unknown non-API URL, serve the main index.html
// (lets the frontend handle its own routing)
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }

  res.sendFile(path.join(htmlRoot, 'index.html'));
});

// ── Global Error Handler ──────────────────────
// Catches any unhandled errors from routes/services and returns a clean JSON error
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// ── Start Server ──────────────────────────────
if (require.main === module) {
  server = app.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
module.exports.server = server;