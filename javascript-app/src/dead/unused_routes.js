/**
 * Dead routes — NOT_REACHABLE (Type C).
 *
 * This file is NEVER required from index.js or any other module.
 * It defines an Express Router, but since nothing imports it,
 * none of these routes are reachable.
 *
 * CVE-2021-23337 (lodash) — NOT_REACHABLE: file never required.
 * CWE-89 (SQL injection) — NOT_REACHABLE: file never required.
 * SECRET — NOT_REACHABLE: file never required.
 */
const express = require('express');
const _ = require('lodash');
const router = express.Router();

// SECRET: Dead admin key (NOT_REACHABLE — file never imported)
const DEAD_ADMIN_KEY = 'sk_dead_express_Np7Wq2xK8m';

router.post('/dead/merge', (req, res) => {
  /** CVE-2021-23337 — NOT_REACHABLE (Type C): lodash merge in dead file. */
  const merged = _.merge({}, req.body);                    // CVE NOT_REACHABLE (Type C)
  res.json({ data: merged, key: DEAD_ADMIN_KEY });         // SECRET NOT_REACHABLE (Type C)
});

router.get('/dead/query', (req, res) => {
  /** CWE-89 — NOT_REACHABLE (Type C): SQL injection in dead file. */
  const sqlite3 = require('better-sqlite3');
  const db = sqlite3(':memory:');
  db.exec('CREATE TABLE IF NOT EXISTS users (name TEXT)');
  const q = req.query.q || '';
  const rows = db.prepare(`SELECT * FROM users WHERE name = '${q}'`).all(); // CWE-89 NOT_REACHABLE (Type C)
  res.json({ results: rows });
});

module.exports = router;
