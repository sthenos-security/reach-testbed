/**
 * Admin routes — NOT_REACHABLE (Type A).
 *
 * This module IS required in index.js, so its top-level code runs,
 * but the Router is never passed to app.use().  No endpoint is
 * reachable via HTTP.
 *
 * CWE-78 (command injection) — NOT_REACHABLE: router never mounted.
 * SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
 */
const express = require('express');
const { execSync } = require('child_process');
const router = express.Router();

// SECRET: Hardcoded admin key (NOT_REACHABLE — router never mounted)
const ADMIN_TOKEN = 'adm_live_express_9fZ83k';

router.post('/admin/exec', (req, res) => {
  /** CWE-78 — NOT_REACHABLE (Type A): imported but never app.use()'d. */
  res.json({ output: execSync(req.body.cmd).toString() }); // CWE-78 NOT_REACHABLE (Type A)
});

router.get('/admin/token', (req, res) => {
  /** SECRET — NOT_REACHABLE (Type A): endpoint unreachable. */
  res.json({ token: ADMIN_TOKEN });                        // SECRET NOT_REACHABLE (Type A)
});

module.exports = router;
