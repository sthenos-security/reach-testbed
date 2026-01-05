/**
 * JavaScript Test App - Known Vulnerabilities
 * 
 * REACHABLE CVEs:
 * - CVE-2021-23337 (lodash prototype pollution) - called in /api/merge
 * - CVE-2022-23529 (jsonwebtoken) - called in /api/verify
 * 
 * UNREACHABLE CVEs:
 * - CVE-2020-28469 (glob-parent ReDoS) - never imported
 */

const express = require('express');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
app.use(express.json());

// ============================================================================
// REACHABLE SECRET
// ============================================================================
const JWT_SECRET = 'super-secret-jwt-key-12345';  // Hardcoded secret
const API_KEY = 'sk_live_xxxxxxxxxxxxxxxxxxxxx';   // Stripe-like key

// ============================================================================
// REACHABLE CVE: lodash prototype pollution
// ============================================================================
app.post('/api/merge', (req, res) => {
    const { base, override } = req.body;
    
    // CVE-2021-23337: _.merge is vulnerable to prototype pollution
    // Attacker can send: {"override": {"__proto__": {"admin": true}}}
    const merged = _.merge({}, base, override);
    
    res.json({ result: merged });
});

// ============================================================================
// REACHABLE CVE: JWT verification bypass
// ============================================================================
app.post('/api/verify', (req, res) => {
    const { token } = req.body;
    
    try {
        // CVE-2022-23529: Algorithm confusion attack possible
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, payload: decoded });
    } catch (err) {
        res.status(401).json({ valid: false, error: err.message });
    }
});

// ============================================================================
// REACHABLE SECRET: API key in request
// ============================================================================
app.get('/api/external', async (req, res) => {
    try {
        // Using hardcoded API key
        const response = await axios.get('https://api.example.com/data', {
            headers: { 'Authorization': `Bearer ${API_KEY}` }
        });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================================
// SAFE ENDPOINT - No vulnerabilities
// ============================================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================================
// UNREACHABLE CODE - glob-parent is in deps but never imported
// ============================================================================
// Note: glob-parent (CVE-2020-28469) is in package.json but never used
// This tests that REACHABLE correctly marks it as UNREACHABLE

function unusedGlobFunction() {
    // This function is never called AND glob-parent isn't even imported
    // const glob = require('glob-parent');
    // glob('**/*.js');
}

// ============================================================================
// MALWARE PATTERN - Suspicious code for detection test
// ============================================================================
function suspiciousCode() {
    // This should trigger SAST rules for obfuscated code
    const encoded = 'Y29uc29sZS5sb2coJ3Rlc3QnKQ==';
    // eval(Buffer.from(encoded, 'base64').toString());  // Commented to not actually execute
}

// ============================================================================
// START SERVER
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
