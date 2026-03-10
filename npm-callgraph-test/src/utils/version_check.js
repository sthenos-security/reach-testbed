/**
 * NOT_REACHABLE: semver CVE-2022-25883 (ReDoS via untrusted version string)
 *
 * This file is NEVER required by server.js or any other file in the import graph.
 * semver 5.7.1 is vulnerable to catastrophic backtracking on crafted version strings.
 *
 * CANARY TEST:
 *   - If semver CVE shows NOT_REACHABLE → JS call graph traversed correctly.
 *   - If semver CVE shows UNKNOWN       → JS call graph did NOT run.
 */

'use strict';

const semver = require('semver');  // CVE-2022-25883

/**
 * Dead-code function — never exported or called from any entrypoint.
 * semver.satisfies() on untrusted input triggers ReDoS.
 */
function checkVersionCompatibility(userInput, range) {
    // CVE-2022-25883: semver.satisfies() with malicious userInput causes ReDoS.
    return semver.satisfies(userInput, range);
}

// Intentionally not exported.
// module.exports = { checkVersionCompatibility };
