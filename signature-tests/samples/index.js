/**
 * Main Entry Point - signature-test-app
 * 
 * This file imports SOME modules but not others.
 * REACHABLE should identify which signatures are in executable code paths.
 */

'use strict';

// These ARE imported and executed - signatures are REACHABLE
const activeLoader = require('./reachable/active_loader');
const liveBeacon = require('./reachable/live_beacon');

// These are NOT imported - signatures are UNREACHABLE
// const deadCode = require('./unreachable/dead_code');
// const unusedModule = require('./unreachable/unused_module');
// const legacyMalware = require('./unreachable/legacy_malware');

function main() {
    console.log('Starting signature test app...');
    
    // Execute reachable code paths
    activeLoader.init();
    liveBeacon.checkin();
    
    console.log('App running. Reachable signatures are active.');
}

// Entry point
main();

module.exports = { main };
