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

const express = require('express');
const cors = require('cors');
const path = require('path');
const logger = require('./utils/logger');

// Import route files — each file handles a group of related API endpoints
const analyseRoutes = require('./routes/analyse');   // Main pipeline: parse+SPF+DKIM+DMARC
const dmarcRoutes   = require('./routes/dmarcRoutes'); // Zircon's DMARC-specific routes

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────
// cors()           — allows the frontend (different port) to call this backend
// express.json()   — lets us read JSON from POST request bodies
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Static Files ──────────────────────────────
// Serve the HTML/CSS/JS frontend files from the /client folder
app.use(express.static(path.join(__dirname, '../client')));

// ── API Routes ────────────────────────────────
// All API calls are prefixed with /api/ to separate them from page URLs
app.use('/api/analyse', analyseRoutes);  // POST /api/analyse/header  → full email check
                                          // POST /api/analyse/domain  → DNS record lookup
                                          // POST /api/analyse/scenario → run demo scenario
app.use('/api/dmarc',   dmarcRoutes);    // DMARC-specific routes (Zircon)

// ── Health Check ──────────────────────────────
// Simple endpoint to confirm the server is running
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Fallback ──────────────────────────────────
// For any unknown URL, serve the main index.html
// (lets the frontend handle its own routing)
//app.get('/*', (req, res) => {
//  res.sendFile(path.join(__dirname, '../client/index.html'));
//});

// ── Global Error Handler ──────────────────────
// Catches any unhandled errors from routes/services and returns a clean JSON error
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// ── Start Server ──────────────────────────────
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});

module.exports = app;