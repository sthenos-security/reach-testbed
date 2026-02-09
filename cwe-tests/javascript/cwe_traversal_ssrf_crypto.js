/**
 * REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
 * CWE-22 (Path Traversal), CWE-918 (SSRF), CWE-502 (Deser)
 * CWE-327 (Weak Crypto), CWE-330 (Weak Random)
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const app = express();
app.use(express.json());

// ============================================================================
// REACHABLE: CWE-22 — Path Traversal (Node.js)
// ============================================================================
app.get('/api/files/:name', (req, res) => {
    // BAD: User-controlled path in readFileSync
    const content = fs.readFileSync('/var/data/' + req.params.name, 'utf8');
    res.json({ content });
});

app.get('/api/download', (req, res) => {
    const file = req.query.file;
    // BAD: path.join doesn't prevent absolute path bypass
    const fullPath = path.join('/uploads', file);
    res.sendFile(fullPath);
});

app.get('/api/logs', (req, res) => {
    const logFile = req.query.name || 'app.log';
    // BAD: path.resolve with user input
    const logPath = path.resolve('/var/logs', logFile);
    const content = fs.readFileSync(logPath, 'utf8');
    res.send(content);
});

// ============================================================================
// REACHABLE: CWE-918 — SSRF (Node.js)
// ============================================================================
app.post('/api/proxy', async (req, res) => {
    const targetUrl = req.body.url;
    // BAD: Fetching user-supplied URL server-side
    const resp = await axios.get(targetUrl);
    res.json(resp.data);
});

app.post('/api/webhook/send', async (req, res) => {
    const endpoint = req.body.endpoint;
    const payload = req.body.payload;
    // BAD: POST to user-controlled endpoint
    await axios.post(endpoint, payload);
    res.json({ sent: true });
});

// ============================================================================
// REACHABLE: CWE-502 — Unsafe Deserialization (node-serialize)
// ============================================================================
app.post('/api/state/restore', (req, res) => {
    const serialized = req.body.state;
    // BAD: eval-based deserialization
    const obj = eval('(' + serialized + ')');
    res.json(obj);
});

// ============================================================================
// REACHABLE: CWE-327 — Weak Crypto (Node.js)
// ============================================================================
app.post('/api/hash', (req, res) => {
    const data = req.body.data;
    // BAD: MD5 for integrity/password
    const hash = crypto.createHash('md5').update(data).digest('hex');
    res.json({ hash });
});

app.post('/api/encrypt', (req, res) => {
    const data = req.body.data;
    // BAD: DES-ECB
    const key = Buffer.from('8bytekey');
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ encrypted });
});

app.post('/api/sign', (req, res) => {
    const data = req.body.data;
    // BAD: SHA1 HMAC
    const hmac = crypto.createHmac('sha1', 'hardcoded-secret').update(data).digest('hex');
    res.json({ signature: hmac });
});

// ============================================================================
// REACHABLE: CWE-330 — Weak Randomness
// ============================================================================
app.get('/api/token', (req, res) => {
    // BAD: Math.random for security token
    const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    res.json({ token });
});

app.get('/api/reset-code', (req, res) => {
    // BAD: Math.random for password reset
    const code = Math.floor(Math.random() * 900000) + 100000;
    res.json({ code });
});

// ============================================================================
// UNREACHABLE
// ============================================================================
function _deadPathTraversal() {
    return fs.readFileSync('../../etc/passwd', 'utf8');
}
function _deadSsrf() {
    axios.get('http://169.254.169.254/latest/meta-data/');
}
function _deadMd5() {
    return crypto.createHash('md5').update('password').digest('hex');
}

app.listen(4002);
module.exports = app;
