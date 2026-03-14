// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — Case 1: External Endpoint (JavaScript)
//
// All functions are REACHABLE via Express HTTP routes.
// Variables are ATTACKER_CONTROLLED (user input flows to sink).
//
// Expected:
//   app_reachability = REACHABLE
//   taint_verdict    = ATTACKER_CONTROLLED
// ============================================================================
'use strict';
const express = require('express');
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');

const app = express();
app.use(express.json());


// ── CWE-89: SQL Injection via HTTP endpoint ────────────────────────────

app.get('/case1/sqli', (req, res) => {
    // REACHABLE + ATTACKER_CONTROLLED: req.query → SQL
    const name = req.query.name;
    const db = require('better-sqlite3')(':memory:');
    db.exec(`SELECT * FROM users WHERE name = '${name}'`);
    res.json({ status: 'ok' });
});


// ── CWE-78: Command Injection via HTTP endpoint ────────────────────────

app.post('/case1/cmdi', (req, res) => {
    // REACHABLE + ATTACKER_CONTROLLED: req.body → shell
    const cmd = req.body.cmd;
    const output = execSync(cmd).toString();
    res.json({ output });
});


// ── CWE-22: Path Traversal via HTTP endpoint ───────────────────────────

app.get('/case1/path', (req, res) => {
    // REACHABLE + ATTACKER_CONTROLLED: req.query → file read
    const filename = req.query.file;
    const content = fs.readFileSync(path.join('/var/data', filename), 'utf8');
    res.json({ content });
});


// ── CWE-918: SSRF via HTTP endpoint ────────────────────────────────────

app.get('/case1/ssrf', (req, res) => {
    // REACHABLE + ATTACKER_CONTROLLED: req.query → URL fetch
    const url = req.query.url;
    http.get(url, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => res.json({ size: data.length }));
    });
});


app.listen(5011, () => console.log('Case 1 JS server on :5011'));
