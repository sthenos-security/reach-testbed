// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — Case 4: Dynamic Invocation (JavaScript)
//
// Tests patterns where static call graph misses function reachability because
// the function reference is computed at runtime.
//
// Each case is annotated with:
//   REACH: expected reachability state
//   CG:    whether static CG catches it (YES / NO / PARTIAL)
//   WHY:   root cause if static CG misses
// ============================================================================
'use strict';
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');

const app = express();
app.use(express.json());


// ── CASE 1: Dict dispatch table (function stored as value) ─────────────────
// REACH: REACHABLE   CG: PARTIAL   CONFIDENCE: MEDIUM
// CG should see dict literal and trace both handler functions as reachable.
// Which one is called depends on runtime key — hence PARTIAL.

function handleCreateUser(data) {
    // CWE-89: SQL injection. Called via handlers[action](data).
    const name = data.name || '';
    const query = `INSERT INTO users (name) VALUES ('${name}')`;  // CWE-89 REACHABLE
    return query;
}

function handleDeleteUser(data) {
    // CWE-89: SQL injection via dict dispatch.
    const id = data.id || '';
    const query = `DELETE FROM users WHERE id=${id}`;  // CWE-89 REACHABLE
    return query;
}

app.post('/dynamic/dispatch', (req, res) => {
    const handlers = {
        create: handleCreateUser,
        delete: handleDeleteUser,
    };
    const fn = handlers[req.body.action];
    if (fn) {
        res.json({ result: fn(req.body) });
    } else {
        res.status(400).json({ error: 'unknown action' });
    }
});


// ── CASE 2: setTimeout / setImmediate callback ─────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
// Static CG should treat setTimeout(fn, delay) as fn being reachable.

function deferredCleanup() {
    // CWE-78: OS command via deferred callback. Registered via setTimeout().
    const dir = process.env.CLEANUP_DIR || '/tmp/sessions';
    execSync(`rm -rf ${dir}/*`);  // CWE-78 REACHABLE
}

app.post('/dynamic/deferred', (req, res) => {
    setTimeout(deferredCleanup, 0);
    res.json({ status: 'queued' });
});


// ── CASE 3: Array.prototype.forEach callback ────────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH

function processItem(item) {
    // CWE-78: called via items.forEach(processItem)
    exec(`process-item ${item.name}`, () => {});  // CWE-78 REACHABLE
}

app.post('/dynamic/foreach', (req, res) => {
    const items = req.body.items || [];
    items.forEach(processItem);
    res.json({ status: 'processed' });
});


// ── CASE 4: Promise.then() callback ───────────────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH

function onFetchSuccess(data) {
    // CWE-78: executed in Promise.then() chain
    const cmd = data.cmd || 'echo ok';
    exec(cmd);  // CWE-78 REACHABLE
}

app.get('/dynamic/promise', (req, res) => {
    const url = req.query.url || 'http://localhost/data';
    fetch(url)
        .then(r => r.json())
        .then(onFetchSuccess)
        .catch(() => {});
    res.json({ status: 'fetching' });
});


// ── CASE 5: eval() with tainted input ─────────────────────────────────────
// REACH: REACHABLE   CG: PARTIAL (sees eval call, not callee)
// The eval() call itself IS reachable and ATTACKER_CONTROLLED.
// What executes inside eval is UNKNOWN statically.

app.post('/dynamic/eval', (req, res) => {
    const expr = req.body.expression;
    // CWE-95: Code injection — user expression → eval
    const result = eval(expr);  // CWE-95 REACHABLE + ATTACKER_CONTROLLED
    res.json({ result });
});


// ── CASE 6: require() with variable module name ────────────────────────────
// REACH: UNKNOWN   CG: NO   CONFIDENCE: LOW
// Module name is runtime-determined — CG cannot resolve the import target.

app.get('/dynamic/require', (req, res) => {
    const plugin = req.query.plugin;
    try {
        // CWE-829: Inclusion of functionality from untrusted control sphere
        const mod = require(`./plugins/${plugin}`);  // CWE-829 UNKNOWN
        res.json({ result: mod.run() });
    } catch (e) {
        res.status(400).json({ error: 'plugin not found' });
    }
});


// ── CASE 7: Function.prototype.call / apply ────────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: MEDIUM

function execWithContext(cmd) {
    // CWE-78: invoked via .call() from an HTTP handler
    execSync(cmd);  // CWE-78 REACHABLE
}

app.post('/dynamic/call-apply', (req, res) => {
    const cmd = req.body.cmd || 'ls /tmp';
    execWithContext.call(null, cmd);
    res.json({ status: 'done' });
});


// ── CASE 8: Computed property key dispatch ─────────────────────────────────
// REACH: UNKNOWN   CG: NO   CONFIDENCE: LOW
// Method selected by user-supplied string — CG cannot resolve at static time.

const handlerObj = {
    readFile(filePath) {
        // CWE-22: path traversal. Called only if action === 'readFile'.
        return fs.readFileSync(filePath, 'utf8');  // CWE-22 UNKNOWN
    },
    writeFile(filePath) {
        // CWE-22: path traversal via write.
        fs.writeFileSync(filePath, 'data');  // CWE-22 UNKNOWN
    },
};

app.post('/dynamic/computed-key', (req, res) => {
    const { action, filePath } = req.body;
    // CWE-22 UNKNOWN: which method executes depends on runtime value of action
    if (typeof handlerObj[action] === 'function') {
        const result = handlerObj[action](filePath);
        res.json({ result });
    } else {
        res.status(400).json({ error: 'unknown action' });
    }
});


// ── CASE 9: Dead code — never registered or referenced ────────────────────
// REACH: NOT_REACHABLE   CG: YES

function deadDynamicHandler(data) {
    // CWE-89: never stored in any dispatch table or passed to any callback
    const id = data.id || '';
    const query = `SELECT * FROM audit WHERE id=${id}`;  // CWE-89 NOT_REACHABLE
    return query;
}


app.listen(5014, () => console.log('Dynamic invocation JS server on :5014'));
