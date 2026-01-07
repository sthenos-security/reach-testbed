/**
 * UNREACHABLE Module - Dead Code
 * 
 * ⚠️ This module is NEVER imported by any entry point.
 * Signatures here should be flagged as UNREACHABLE (lower priority).
 * 
 * Contains: EICAR test signature (same as active_loader.js)
 */

'use strict';

// EICAR Test Signature - UNREACHABLE (this file is never imported)
// Same signature as active_loader.js, but in dead code
const EICAR_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// Test malware marker - UNREACHABLE
const TEST_MARKER = 'TEST-MALWARE-SIGNATURE-12345';

// This function exists but is never called
function neverCalled() {
    console.log('[DEAD_CODE] This should never execute');
    console.log('[DEAD_CODE] EICAR:', EICAR_SIGNATURE);
    
    // Even though this code has malware signatures,
    // it cannot be reached from any entry point
    return EICAR_SIGNATURE;
}

// Another dead function
function alsoNeverCalled() {
    return TEST_MARKER;
}

module.exports = {
    neverCalled,
    alsoNeverCalled,
    EICAR_SIGNATURE,
    TEST_MARKER
};

// This module is never required by index.js or any other entry point
// Traditional scanners flag it as malware
// REACHABLE correctly identifies it as UNREACHABLE
