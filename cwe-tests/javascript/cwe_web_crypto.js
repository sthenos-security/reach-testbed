/**
 * CWE-22 (Path Traversal), CWE-79 (XSS), CWE-918 (SSRF), CWE-502 (Deser)
 * CWE-327 (Weak Crypto), CWE-330 (Weak Random)
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const { serialize, unserialize } = require('php-serialize');
const app = express();
app.use(express.json());

// REACHABLE: CWE-22 — Path Traversal
app.get('/api/files', (req, res) => {
    const name = req.query.name;
    const content = fs.readFileSync(path.join('/var/data', name), 'utf8');
    res.json({ content });
});

app.get('/api/download', (req, res) => {
    const filepath = req.query.path;
    res.sendFile(filepath);  // BAD: absolute path from user
});

app.get('/api/logs/:filename', (req, res) => {
    const content = fs.readFileSync(`/var/log/${req.params.filename}`, 'utf8');
    res.send(content);
});

// REACHABLE: CWE-79 — XSS (reflected)
app.get('/api/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<html><body>Hello ${name}</body></html>`);
});

app.get('/api/error', (req, res) => {
    res.send(`<div class="error">${req.query.msg}</div>`);
});

app.get('/api/search', (req, res) => {
    const q = req.query.q;
    res.send(`<p>Results for: <b>${q}</b></p>`);
});

// REACHABLE: CWE-918 — SSRF
app.post('/api/fetch', (req, res) => {
    const url = req.body.url;
    axios.get(url).then(r => res.json({ data: r.data })).catch(e => res.status(500).json({ error: e.message }));
});

app.post('/api/webhook', (req, res) => {
    axios.post(req.body.callback, { event: 'ping' });
    res.json({ sent: true });
});

// REACHABLE: CWE-327 — Weak crypto (MD5, SHA1, DES)
app.post('/api/hash', (req, res) => {
    const data = req.body.data;
    const md5 = crypto.createHash('md5').update(data).digest('hex');
    const sha1 = crypto.createHash('sha1').update(data).digest('hex');
    res.json({ md5, sha1 });
});

app.post('/api/encrypt', (req, res) => {
    const key = Buffer.from('0123456789abcdef');
    const iv = Buffer.alloc(8, 0);
    const cipher = crypto.createCipheriv('des-cbc', key.slice(0, 8), iv);
    let encrypted = cipher.update(req.body.data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ encrypted });
});

// REACHABLE: CWE-330 — Weak random for tokens
app.get('/api/token', (req, res) => {
    const token = Math.random().toString(36).substring(2);
    res.json({ token });
});

app.get('/api/reset-code', (req, res) => {
    const code = Math.floor(Math.random() * 999999).toString().padStart(6, '0');
    res.json({ code });
});

// REACHABLE: CWE-1275 — Insecure cookie
app.post('/api/login', (req, res) => {
    res.cookie('session', 'abc123');  // no httpOnly, secure, sameSite
    res.json({ ok: true });
});

// UNREACHABLE
function _deadTraversal() { fs.readFileSync('../../etc/shadow'); }
function _deadSsrf() { axios.get('http://169.254.169.254/latest/meta-data/'); }
function _deadMd5() { crypto.createHash('md5').update('pw').digest('hex'); }

app.listen(4002);
