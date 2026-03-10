'use strict';
/**
 * UNKNOWN: CWE — module required, only safe export called.
 * Vulnerable functions exist but have no call path from server.js.
 */
const { execSync } = require('child_process');

/** Safe export — called from server.js. */
function sanitize(str) {
    return str.replace(/[^\w\s]/g, '');
}

/** CWE-78 UNKNOWN: command injection. Module required but this never called. */
function commandInjectionUnknown(cmd) {
    return execSync(cmd).toString(); // CWE-78: UNKNOWN
}

/** CWE-89 UNKNOWN: SQL injection string. Module required but never called. */
function sqlInjectionUnknown(db, name) {
    return db.query(`SELECT * FROM users WHERE name='${name}'`); // CWE-89: UNKNOWN
}

module.exports = { sanitize, commandInjectionUnknown, sqlInjectionUnknown };
