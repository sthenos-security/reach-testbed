// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// CWE-327 (Broken Crypto), CWE-328 (Weak Hash), CWE-330 (Weak PRNG)
// CWE-326 (Insufficient Key Size)
// ===========================================================================
const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// ── REACHABLE: CWE-328 — Weak Hash (MD5 for passwords) ───────────────────
app.post('/api/auth/hash', (req, res) => {
    const password = req.body.password;
    const hash = crypto.createHash('md5').update(password).digest('hex');
    res.json({ hash });
});

app.post('/api/verify/checksum', (req, res) => {
    const data = req.body.data;
    const sha1 = crypto.createHash('sha1').update(data).digest('hex');
    res.json({ sha1 });
});

// ── REACHABLE: CWE-327 — Broken Cipher (DES, RC4) ───────────────────────
app.post('/api/encrypt/des', (req, res) => {
    const key = Buffer.from('8byteskey!!12345'.slice(0, 8));
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    let encrypted = cipher.update(req.body.data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ ciphertext: encrypted });
});

app.post('/api/encrypt/rc4', (req, res) => {
    const key = Buffer.from('weakrc4key');
    const cipher = crypto.createCipheriv('rc4', key, null);
    let encrypted = cipher.update(req.body.data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ ciphertext: encrypted });
});

// ── REACHABLE: CWE-327 — AES-ECB (pattern leak) ─────────────────────────
app.post('/api/encrypt/aes-ecb', (req, res) => {
    const key = Buffer.from('0123456789abcdef0123456789abcdef');
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    let encrypted = cipher.update(req.body.data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ ciphertext: encrypted });
});

// ── REACHABLE: CWE-330 — Weak PRNG for security ─────────────────────────
app.get('/api/token', (req, res) => {
    // BAD: Math.random is not cryptographically secure
    const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    res.json({ token });
});

app.get('/api/session-id', (req, res) => {
    const sid = Array.from({length: 32}, () => 
        'abcdef0123456789'[Math.floor(Math.random() * 16)]
    ).join('');
    res.json({ session_id: sid });
});

app.get('/api/otp', (req, res) => {
    const otp = Math.floor(100000 + Math.random() * 900000);
    res.json({ otp });
});

// ── REACHABLE: CWE-798 — Hardcoded Crypto Keys ──────────────────────────
const HMAC_KEY = 'super-secret-hmac-key-hardcoded-2024';
const AES_KEY = Buffer.from('ThisIsAHardcodedAESKey!1234567890'.slice(0, 32));

app.post('/api/sign', (req, res) => {
    const sig = crypto.createHmac('sha256', HMAC_KEY).update(req.body.data).digest('hex');
    res.json({ signature: sig });
});

app.post('/api/encrypt/hardcoded', (req, res) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
    let encrypted = cipher.update(req.body.data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ iv: iv.toString('hex'), ciphertext: encrypted });
});

// ── UNREACHABLE ──────────────────────────────────────────────────────────
function deadMd5() { return crypto.createHash('md5').update('dead').digest('hex'); }
function deadWeakRandom() { return Math.random() * 999999; }

app.listen(4004);
module.exports = app;
