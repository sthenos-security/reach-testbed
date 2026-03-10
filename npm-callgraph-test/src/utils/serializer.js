/**
 * NOT_REACHABLE: node-serialize CVE-2017-5941 (RCE via unserialize)
 *
 * This file is NEVER required by server.js or any other file in the import graph.
 * It exists so that Grype finds node-serialize in the SBOM, but since no
 * entrypoint ever imports this module the JS call graph must mark it NOT_REACHABLE.
 *
 * CANARY TEST:
 *   - If node-serialize CVE shows NOT_REACHABLE → JS call graph ran correctly.
 *   - If node-serialize CVE shows UNKNOWN       → JS call graph did NOT run.
 *
 * Attacker payload: {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
 */

'use strict';

const serialize = require('node-serialize');  // CVE-2017-5941

/**
 * Dead-code function — never exported or called.
 * node-serialize's unserialize() executes embedded JS functions.
 */
function deserializeUserSession(raw) {
    // CVE-2017-5941: unserialize() calls eval() on function literals.
    return serialize.unserialize(raw);
}

// Intentionally not exported — this module is never required.
// module.exports = { deserializeUserSession };
