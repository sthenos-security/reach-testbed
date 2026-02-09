// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// CWE-89 (SQLi), CWE-943 (NoSQLi), CWE-78 (Command Injection)
// ===========================================================================
const express = require('express');
const mysql = require('mysql2');
const { MongoClient } = require('mongodb');
const { exec, execSync } = require('child_process');

const app = express();
app.use(express.json());

const db = mysql.createPool({ host: 'localhost', user: 'root', password: 'root', database: 'test' });

// ── REACHABLE: CWE-89 — SQL Injection (string concat) ─────────────────────
app.get('/api/users', (req, res) => {
    const name = req.query.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'", (err, rows) => {
        res.json(rows || []);
    });
});

// REACHABLE: CWE-89 — SQL Injection (template literal)
app.get('/api/orders', (req, res) => {
    const sort = req.query.sort || 'id';
    db.query(`SELECT * FROM orders ORDER BY ${sort}`, (err, rows) => {
        res.json(rows || []);
    });
});

// REACHABLE: CWE-89 — SQL Injection (string format)
app.delete('/api/users/:id', (req, res) => {
    const id = req.params.id;
    db.query("DELETE FROM users WHERE id = " + id, (err) => {
        res.json({ deleted: true });
    });
});

// ── REACHABLE: CWE-943 — NoSQL Injection ──────────────────────────────────
app.post('/api/login', async (req, res) => {
    const client = new MongoClient('mongodb://localhost:27017');
    const db = client.db('app');
    // BAD: User object passed directly — {"username": {"$gt": ""}, "password": {"$gt": ""}}
    const user = await db.collection('users').findOne(req.body);
    res.json(user || { error: 'not found' });
});

app.get('/api/products', async (req, res) => {
    const client = new MongoClient('mongodb://localhost:27017');
    const db = client.db('app');
    // BAD: req.query goes straight into find
    const products = await db.collection('products').find(req.query).toArray();
    res.json(products);
});

// ── REACHABLE: CWE-78 — OS Command Injection ─────────────────────────────
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.json({ output: stdout });
    });
});

app.post('/api/convert', (req, res) => {
    const filename = req.body.filename;
    const output = execSync(`convert ${filename} output.pdf`);
    res.json({ result: output.toString() });
});

app.get('/api/lookup', (req, res) => {
    const domain = req.query.domain;
    exec('nslookup ' + domain, (err, stdout) => {
        res.json({ dns: stdout });
    });
});

// ── UNREACHABLE ────────────────────────────────────────────────────────────
function deadSqli() {
    db.query("SELECT * FROM secrets WHERE key = '" + "admin' OR 1=1--" + "'");
}

function deadCommandInjection() {
    exec('rm -rf ' + '/tmp/test; cat /etc/passwd');
}

app.listen(4001);
module.exports = app;
