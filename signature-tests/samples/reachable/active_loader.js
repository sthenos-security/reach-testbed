/**
 * REACHABLE Module - Active Loader
 * 
 * This module IS imported by index.js, so signatures here are REACHABLE.
 * REACHABLE should flag these as CRITICAL.
 * 
 * Contains: EICAR test signature, obfuscation patterns
 */

'use strict';

// EICAR Test Signature - REACHABLE from index.js
// This is the industry-standard antivirus test string
const EICAR_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// Test malware marker - REACHABLE
const TEST_MARKER = 'TEST-MALWARE-SIGNATURE-12345';

// Base64 obfuscation pattern - REACHABLE
const OBFUSCATED_PAYLOAD = 'VEVTVC1NQUxXQVJFLVNJR05BVFVSRS0xMjM0NQ==';

function init() {
    console.log('[ACTIVE_LOADER] Initializing...');
    
    // Simulate checking for signature (triggers detection)
    if (EICAR_SIGNATURE.includes('EICAR')) {
        console.log('[ACTIVE_LOADER] EICAR signature present');
    }
    
    // Simulate marker check
    if (TEST_MARKER.startsWith('TEST-MALWARE')) {
        console.log('[ACTIVE_LOADER] Test marker active');
    }
    
    return true;
}

function decode(payload) {
    // Obfuscation pattern - decodes base64
    return Buffer.from(payload, 'base64').toString();
}

module.exports = {
    init,
    decode,
    EICAR_SIGNATURE,
    TEST_MARKER
};
