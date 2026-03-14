// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — Case 3: Dead Code (JavaScript)
//
// Functions are NEVER called — not from routes, not from timers, not from
// any trigger. The module is NOT required by any entrypoint.
//
// Expected:
//   app_reachability = NOT_REACHABLE
//   taint_verdict    = N/A
// ============================================================================
'use strict';
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');


function deadSqli(db, userInput) {
    // CWE-89: NOT_REACHABLE — never called, module never loaded
    return db.query(`SELECT * FROM users WHERE name = '${userInput}'`);
}

function deadCmdi(cmd) {
    // CWE-78: NOT_REACHABLE — never called
    return execSync(cmd).toString();
}

function deadPathTraversal(filename) {
    // CWE-22: NOT_REACHABLE — never called
    return fs.readFileSync(path.join('/var/data', filename), 'utf8');
}

function deadSsrf(url) {
    // CWE-918: NOT_REACHABLE — never called
    const http = require('http');
    return new Promise((resolve) => {
        http.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
        });
    });
}

function deadEval(code) {
    // CWE-94: NOT_REACHABLE — never called
    return eval(code);
}

// This file has NO:
// - Express routes
// - setInterval/setTimeout
// - process.on handlers
// - IIFE or module-level calls
// - Class instantiation
// Pure dead code.

module.exports = { deadSqli, deadCmdi, deadPathTraversal, deadSsrf, deadEval };
