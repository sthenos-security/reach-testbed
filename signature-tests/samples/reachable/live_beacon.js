/**
 * REACHABLE Module - Live Beacon
 * 
 * This module IS imported by index.js, so signatures here are REACHABLE.
 * REACHABLE should flag these as CRITICAL.
 * 
 * Contains: C2 beacon patterns, exfiltration markers
 */

'use strict';

const https = require('https');

// C2 Beacon markers - REACHABLE from index.js
const C2_CALLBACK = 'REACHABLE_TEST_BEACON::C2_CALLBACK';
const BEACON_CHECKIN = 'TEST_BEACON_CHECKIN';

// Simulated C2 endpoints (safe .test TLD)
const C2_ENDPOINTS = [
    'https://c2.attacker.test/beacon',
    'https://malware.evil.test/callback',
    'https://exfil.badguy.test/collect'
];

// Exfiltration marker - REACHABLE
const EXFIL_MARKER = 'EXFIL_TEST_MARKER';
const DATA_THEFT = 'DATA_THEFT_SIMULATION';

function checkin() {
    console.log('[LIVE_BEACON] Beacon check-in...');
    console.log('[LIVE_BEACON] Marker:', C2_CALLBACK);
    
    // Simulate C2 communication (will fail - .test domains don't resolve)
    C2_ENDPOINTS.forEach(endpoint => {
        console.log('[LIVE_BEACON] Would contact:', endpoint);
    });
    
    return { status: 'simulated', marker: BEACON_CHECKIN };
}

function exfiltrate(data) {
    console.log('[LIVE_BEACON] Exfiltration simulation:', EXFIL_MARKER);
    console.log('[LIVE_BEACON] Data theft marker:', DATA_THEFT);
    
    // This code IS reachable - should be flagged
    return { exfiltrated: false, marker: EXFIL_MARKER };
}

module.exports = {
    checkin,
    exfiltrate,
    C2_CALLBACK,
    C2_ENDPOINTS
};
