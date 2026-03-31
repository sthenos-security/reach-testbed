/**
 * UNREACHABLE Module - Unused Module
 *
 * ⚠️ This module is NEVER imported by any entry point.
 * Signatures here should be flagged as UNREACHABLE (lower priority).
 *
 * Demonstrates: REACHABLE deprioritises findings in code that can never execute.
 * Traditional scanners treat this identically to active_loader.js — both "CRITICAL".
 * REACHABLE surfaces active_loader.js as CRITICAL and this as NOT_REACHABLE.
 */

'use strict';

// Ransomware marker — UNREACHABLE (this file is never imported)
const RANSOM_START = 'FAKE_RANSOMWARE_MARKER::ENCRYPT_START';
const RANSOM_KEY   = 'FAKE_RANSOMWARE_MARKER::DECRYPT_KEY';
const RANSOM_MSG   = 'YOUR_FILES_ARE_ENCRYPTED_TEST';

// C2 beacon — UNREACHABLE
const C2_CALLBACK  = 'REACHABLE_TEST_BEACON::C2_CALLBACK';
const BEACON       = 'TEST_BEACON_CHECKIN';

// These functions exist but are never called from any reachable entry point
function encryptFiles() {
    console.log('[UNUSED_MODULE] Ransomware simulation (never reachable)');
    return { marker: RANSOM_START, key: RANSOM_KEY, msg: RANSOM_MSG };
}

function callHome() {
    console.log('[UNUSED_MODULE] C2 beacon (never reachable):', C2_CALLBACK);
    return BEACON;
}

function mineCoins() {
    // Crypto miner marker — UNREACHABLE
    const POOL = 'stratum+tcp://mine.fake-pool.test';
    console.log('[UNUSED_MODULE] Mining pool (never reachable):', POOL);
    return POOL;
}

module.exports = {
    encryptFiles,
    callHome,
    mineCoins,
    RANSOM_START,
    C2_CALLBACK,
};

// This module is never required by index.js or any live entry point.
// Traditional scanner: ⚠️ RANSOMWARE + C2 + CRYPTO_MINER detected (CRITICAL ×3)
// REACHABLE:          ⬜ NOT_REACHABLE — no call path from any entrypoint
