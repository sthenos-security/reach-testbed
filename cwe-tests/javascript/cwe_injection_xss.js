/**
 * REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
 * CWE-79 (XSS), CWE-89 (SQLi), CWE-78 (Command Injection)
 * CWE-94 (Code Injection), CWE-1321 (Prototype Pollution)
 */
const express = require('express');
const { exec, execSync } = require('child_process');
const mysql = require('mysql2');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// REACHABLE: CWE-79 — Reflected XSS
// ============================================================================
app.get('/search', (req, res) => {
    const query = req.query.q || '';
    // BAD: User input directly in HTML response
    res.send(`<h1>Results for: ${query}</h1><div>No results found</div>`);
});

app.get('/profile', (req, res) => {
    const name = req.query.name || '';
    // BAD: innerHTML-style injection
    res.send(`<div class="profile"><span>${name}</span></div>`);
});

// REACHABLE: CWE-79 — Stored XSS pattern
app.post('/api/comments', (req, res) => {
    const comment = req.body.comment || '';
    // BAD: Storing unsanitized HTML for later rendering
    const rendered = `<div class="comment">${comment}</div>`;
    res.json({ html: rendered });
});

// ============================================================================
// REACHABLE: CWE-89 — SQL Injection (Node.js)
// ============================================================================
app.get('/api/users', (req, res) => {
    const name = req.query.name;
    const conn = mysql.createConnection({ host: 'localhost', user: 'root', database: 'test' });
    // BAD: String concatenation in SQL
    conn.query("SELECT * FROM users WHERE name = '" + name + "'", (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/orders', (req, res) => {
    const status = req.query.status;
    const conn = mysql.createConnection({ host: 'localhost', user: 'root', database: 'test' });
    // BAD: Template literal in SQL
    conn.query(`SELECT * FROM orders WHERE status = '${status}'`, (err, rows) => {
        res.json(rows || []);
    });
});

// ============================================================================
// REACHABLE: CWE-78 — OS Command Injection (Node.js)
// ============================================================================
app.get('/api/lookup', (req, res) => {
    const domain = req.query.domain;
    // BAD: User input in exec()
    exec(`dig ${domain}`, (err, stdout) => {
        res.json({ result: stdout });
    });
});

app.get('/api/convert', (req, res) => {
    const filename = req.query.file;
    // BAD: execSync with user input
    const result = execSync(`convert ${filename} output.png`);
    res.json({ status: 'converted' });
});

app.post('/api/git/clone', (req, res) => {
    const repoUrl = req.body.url;
    // BAD: User-controlled URL in exec
    exec(`git clone ${repoUrl} /tmp/repo`, (err) => {
        res.json({ status: err ? 'failed' : 'cloned' });
    });
});

// ============================================================================
// REACHABLE: CWE-94 — Code Injection via eval
// ============================================================================
app.post('/api/eval', (req, res) => {
    const code = req.body.expression;
    // BAD: eval on user input
    const result = eval(code);
    res.json({ result });
});

app.post('/api/template', (req, res) => {
    const tmpl = req.body.template;
    // BAD: Function constructor = eval equivalent
    const fn = new Function('data', tmpl);
    const result = fn(req.body.data || {});
    res.json({ result });
});

// ============================================================================
// REACHABLE: CWE-1321 — Prototype Pollution
// ============================================================================
app.post('/api/config/merge', (req, res) => {
    const defaults = { theme: 'light', lang: 'en' };
    const userConfig = req.body;
    // BAD: Recursive merge without __proto__ check
    function deepMerge(target, source) {
        for (const key in source) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                target[key] = target[key] || {};
                deepMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
        return target;
    }
    const merged = deepMerge(defaults, userConfig);
    res.json(merged);
});

// ============================================================================
// UNREACHABLE variants
// ============================================================================
function _deadXss() {
    return `<div>${"<script>alert(1)</script>"}</div>`;
}
function _deadSqli() {
    const conn = mysql.createConnection({});
    conn.query("DROP TABLE users WHERE 1='" + "x" + "'");
}
function _deadExec() {
    exec("rm -rf /tmp/*");
}

app.listen(4001);
module.exports = app;
