/**
 * REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
 * CWE-89 (SQLi), CWE-78 (Command Injection), CWE-79 (XSS), CWE-22 (Path Traversal)
 * CWE-94 (Code Injection), CWE-918 (SSRF), CWE-502 (Deserialization)
 */
const express = require('express');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const serialize = require('node-serialize');

const app = express();
app.use(express.json());

// ============================================================================
// REACHABLE: CWE-89 — SQL Injection (template literal)
// ============================================================================
app.get('/api/users', (req, res) => {
    const name = req.query.name;
    const db = require('better-sqlite3')('/tmp/test.db');
    // BAD: template literal in SQL
    const rows = db.prepare(`SELECT * FROM users WHERE name = '${name}'`).all();
    res.json(rows);
});

// REACHABLE: CWE-89 — SQL Injection (string concat)
app.get('/api/products', (req, res) => {
    const cat = req.query.category;
    const db = require('better-sqlite3')('/tmp/test.db');
    // BAD: string concatenation
    const rows = db.prepare("SELECT * FROM products WHERE cat = '" + cat + "'").all();
    res.json(rows);
});

// ============================================================================
// REACHABLE: CWE-78 — OS Command Injection
// ============================================================================
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    // BAD: user input in shell command
    const result = execSync(`ping -c 1 ${host}`).toString();
    res.json({ result });
});

app.post('/api/convert', (req, res) => {
    const filename = req.body.file;
    // BAD: user input in exec
    exec(`convert ${filename} output.pdf`, (err, stdout) => {
        res.json({ output: stdout || err?.message });
    });
});

app.get('/api/whois', (req, res) => {
    const domain = req.query.domain;
    // BAD: backtick injection
    const result = execSync('whois ' + domain).toString();
    res.json({ result });
});

// ============================================================================
// REACHABLE: CWE-79 — Cross-Site Scripting
// ============================================================================
app.get('/api/greet', (req, res) => {
    const name = req.query.name;
    // BAD: reflected XSS
    res.send(`<h1>Hello ${name}!</h1>`);
});

app.get('/api/error', (req, res) => {
    const msg = req.query.msg;
    // BAD: error message reflected in HTML
    res.send(`<div class="alert alert-danger">${msg}</div>`);
});

// ============================================================================
// REACHABLE: CWE-22 — Path Traversal
// ============================================================================
app.get('/api/files/:name', (req, res) => {
    const filePath = path.join('/var/uploads', req.params.name);
    // BAD: path.join doesn't prevent ../
    res.sendFile(filePath);
});

app.get('/api/logs', (req, res) => {
    const logFile = req.query.file;
    // BAD: direct user input as file path
    const content = fs.readFileSync(logFile, 'utf8');
    res.json({ content });
});

app.delete('/api/files/remove', (req, res) => {
    const target = req.query.path;
    // BAD: arbitrary file deletion
    fs.unlinkSync(target);
    res.json({ deleted: true });
});

// ============================================================================
// REACHABLE: CWE-94 — Code Injection
// ============================================================================
app.post('/api/eval', (req, res) => {
    const code = req.body.code;
    // BAD: eval on user input
    const result = eval(code);
    res.json({ result });
});

app.post('/api/run', (req, res) => {
    const fn = req.body.function;
    // BAD: Function constructor with user input
    const func = new Function('data', fn);
    const result = func(req.body.data);
    res.json({ result });
});

// ============================================================================
// REACHABLE: CWE-918 — SSRF
// ============================================================================
app.post('/api/fetch', async (req, res) => {
    const url = req.body.url;
    // BAD: server-side fetch of user-supplied URL
    const resp = await axios.get(url);
    res.json({ data: resp.data });
});

app.post('/api/webhook', async (req, res) => {
    const callback = req.body.callback_url;
    // BAD: SSRF via webhook
    await axios.post(callback, { event: 'test' });
    res.json({ sent: true });
});

// ============================================================================
// REACHABLE: CWE-502 — Unsafe Deserialization
// ============================================================================
app.post('/api/deserialize', (req, res) => {
    const data = req.body.serialized;
    // BAD: node-serialize is vulnerable to RCE
    const obj = serialize.unserialize(data);
    res.json({ result: obj });
});

// ============================================================================
// REACHABLE: CWE-327/328 — Weak Crypto
// ============================================================================
const crypto = require('crypto');

app.post('/api/hash', (req, res) => {
    const data = req.body.data;
    // BAD: MD5 for integrity
    const hash = crypto.createHash('md5').update(data).digest('hex');
    res.json({ md5: hash });
});

app.post('/api/hash/password', (req, res) => {
    const password = req.body.password;
    // BAD: SHA1 for password hashing
    const hash = crypto.createHash('sha1').update(password).digest('hex');
    res.json({ hash });
});

// ============================================================================
// REACHABLE: CWE-200 — Information Exposure
// ============================================================================
app.get('/api/debug', (req, res) => {
    // BAD: leaks environment
    res.json({ env: process.env, cwd: process.cwd(), versions: process.versions });
});

// UNREACHABLE: dead code
function _deadSqli() {
    const db = require('better-sqlite3')('/tmp/t.db');
    db.prepare("DROP TABLE users WHERE 1='" + "x" + "'").run();
}
function _deadCmd() { execSync('rm -rf /tmp/' + 'user_input'); }
function _deadEval() { eval('process.exit(1)'); }
function _deadSsrf() { axios.get('http://169.254.169.254/latest/meta-data/'); }

const PORT = 3001;
app.listen(PORT, () => console.log(`CWE tests on ${PORT}`));
