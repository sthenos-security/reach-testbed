// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// CWE-918 (SSRF), CWE-1321 (Prototype Pollution), CWE-502 (Deser)
// ===========================================================================
const express = require('express');
const axios = require('axios');
const _ = require('lodash');
const vm = require('vm');
const { serialize, deserialize } = require('node-serialize');

const app = express();
app.use(express.json());

// ── REACHABLE: CWE-918 — SSRF ───────────────────────────────────────────
app.post('/api/fetch', async (req, res) => {
    const url = req.body.url;
    const resp = await axios.get(url, { timeout: 5000 });
    res.json({ status: resp.status, data: resp.data });
});

app.post('/api/webhook', async (req, res) => {
    const callback = req.body.callback_url;
    await axios.post(callback, { event: 'test', ts: Date.now() });
    res.json({ sent: true });
});

app.get('/api/proxy', async (req, res) => {
    const target = req.query.url;
    const resp = await axios.get(target, { responseType: 'arraybuffer' });
    res.set('Content-Type', resp.headers['content-type']);
    res.send(resp.data);
});

// ── REACHABLE: CWE-1321 — Prototype Pollution ──────────────────────────
app.post('/api/merge', (req, res) => {
    const base = { role: 'user', active: true };
    // BAD: _.merge is vulnerable — {"__proto__": {"admin": true}}
    const merged = _.merge({}, base, req.body);
    res.json(merged);
});

app.post('/api/config/update', (req, res) => {
    const config = { debug: false, logLevel: 'info' };
    // BAD: recursive merge with user input
    const updated = deepMerge(config, req.body);
    res.json(updated);
});

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

// ── REACHABLE: CWE-502 — Unsafe Deserialization ────────────────────────
app.post('/api/restore', (req, res) => {
    const serialized = req.body.data;
    // BAD: node-serialize with user input enables RCE
    const obj = deserialize(serialized);
    res.json(obj);
});

// ── REACHABLE: Unsafe eval / vm ────────────────────────────────────────
app.post('/api/eval', (req, res) => {
    const code = req.body.expression;
    // BAD: eval on user input
    const result = eval(code);
    res.json({ result });
});

app.post('/api/sandbox', (req, res) => {
    const code = req.body.code;
    // BAD: vm.runInNewContext is not a security sandbox
    const result = vm.runInNewContext(code, { require, console, process });
    res.json({ result: String(result) });
});

// ── UNREACHABLE ──────────────────────────────────────────────────────────
function deadSsrf() { axios.get('http://169.254.169.254/latest/meta-data/'); }
function deadProto() { _.merge({}, JSON.parse('{"__proto__":{"pwned":true}}')); }
function deadDeser() { deserialize('{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}'); }

app.listen(4005);
module.exports = app;
