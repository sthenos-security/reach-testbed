// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// CWE-287 (Broken Auth), CWE-639 (IDOR), CWE-352 (CSRF)
// CWE-307 (Brute Force), CWE-613 (Session Expiration)
// ===========================================================================
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const JWT_SECRET = 'hardcoded-jwt-secret-2024';
const USERS = { admin: { pass: 'admin123', role: 'admin' }, user1: { pass: 'pass', role: 'user' } };

// ── REACHABLE: CWE-287 — No Auth on Sensitive Endpoints ──────────────────
app.get('/api/admin/users', (req, res) => {
    res.json(Object.keys(USERS).map(u => ({ username: u, role: USERS[u].role })));
});

app.delete('/api/admin/user/:id', (req, res) => {
    res.json({ deleted: req.params.id });
});

app.get('/api/admin/config', (req, res) => {
    res.json({ db: 'postgres://admin:secret@db:5432/prod', redis: 'redis://:pass@cache:6379' });
});

// ── REACHABLE: CWE-287 — JWT None Algorithm ─────────────────────────────
app.post('/api/auth/verify', (req, res) => {
    const token = req.body.token;
    // BAD: algorithms not restricted — accepts "none"
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ user: decoded });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS[username];
    if (user && user.pass === password) {
        // BAD: No expiration on JWT
        const token = jwt.sign({ user: username, role: user.role }, JWT_SECRET);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'invalid' });
    }
});

// ── REACHABLE: CWE-639 — IDOR ──────────────────────────────────────────
app.get('/api/users/:id/profile', (req, res) => {
    res.json({ id: req.params.id, email: `user${req.params.id}@corp.com`, ssn: '123-45-6789', salary: 150000 });
});

app.get('/api/documents/:id', (req, res) => {
    res.json({ id: req.params.id, content: 'Confidential merger docs', classification: 'SECRET' });
});

app.put('/api/users/:id/role', (req, res) => {
    res.json({ id: req.params.id, newRole: req.body.role });
});

// ── REACHABLE: CWE-352 — No CSRF Protection ────────────────────────────
app.post('/api/transfer', (req, res) => {
    const { to, amount } = req.body;
    // BAD: No CSRF token, no origin check
    res.json({ transferred: amount, to });
});

app.post('/api/password/change', (req, res) => {
    const { newPassword } = req.body;
    // BAD: No old password verification, no CSRF
    res.json({ status: 'changed' });
});

// ── REACHABLE: CWE-307 — No Rate Limiting ──────────────────────────────
app.post('/api/auth/otp', (req, res) => {
    const { otp } = req.body;
    if (otp === '123456') return res.json({ valid: true });
    res.status(401).json({ valid: false });
});

// ── REACHABLE: CWE-613 — Permanent Cookies ─────────────────────────────
app.post('/api/auth/remember', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.cookie('auth', token, { maxAge: 365 * 24 * 60 * 60 * 1000, httpOnly: false, secure: false });
    res.json({ remembered: true });
});

// ── UNREACHABLE ──────────────────────────────────────────────────────────
function deadAuth() { return jwt.sign({ admin: true }, 'dead-secret'); }
function deadIdor() { return { ssn: '000-00-0000', salary: 0 }; }

app.listen(4006);
module.exports = app;
