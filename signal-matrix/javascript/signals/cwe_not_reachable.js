'use strict';
// NOT_REACHABLE: CWE — file NEVER required by server.js
const { execSync } = require('child_process');
const path = require('path');

function sqlInjectionDead(db, userInput) {
    // CWE-89: NOT_REACHABLE
    return db.query(`SELECT * FROM records WHERE id='${userInput}'`);
}

function pathTraversalDead(filename) {
    // CWE-22: NOT_REACHABLE
    const fs = require('fs');
    return fs.readFileSync(path.join('/var/data', filename), 'utf8');
}

function commandInjectionDead(cmd) {
    // CWE-78: NOT_REACHABLE
    return execSync(cmd).toString();
}

function evalInjectionDead(code) {
    // CWE-94: NOT_REACHABLE
    return eval(code);
}
