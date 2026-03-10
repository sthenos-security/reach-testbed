'use strict';
/**
 * Signal Matrix — JavaScript entrypoint
 *
 * Requires ONLY reachable and unknown modules.
 * NOT_REACHABLE modules are never required here.
 *
 * UNKNOWN pattern: module IS required but only its safe export is used.
 * The vulnerable function exists in the module but has no call path from here.
 */

const express = require('express');
const _       = require('lodash');              // CVE REACHABLE

// UNKNOWN: marked required but only safeText() called, not parseMarkdownUnknown()
const { safeText }         = require('./signals/cve_unknown');
// UNKNOWN: cwe_unknown required but only sanitize() called, not sqlInjectionUnknown()
const { sanitize }         = require('./signals/cwe_unknown');
// UNKNOWN: secret_unknown required but only getPublicKey() called, not getPrivateKeyUnknown()
const { getPublicKey }     = require('./signals/secret_unknown');
// UNKNOWN: dlp_unknown required but only getAnonProfile() called, not exportPiiUnknown()
const { getAnonProfile }   = require('./signals/dlp_unknown');
// UNKNOWN: ai_unknown required but only getCapabilities() called, not runUncheckedLlmUnknown()
const { getCapabilities }  = require('./signals/ai_unknown');

// REACHABLE signals
const { mergeObjects }     = require('./signals/cve_reachable');
const { renderHtml }       = require('./signals/cwe_reachable');
const { getApiKey }        = require('./signals/secret_reachable');
const { processUserPii }   = require('./signals/dlp_reachable');
const { callLlm }          = require('./signals/ai_reachable');
const { initBeacon }       = require('./signals/malware_reachable');

// NOT_REACHABLE modules are NEVER required:
//   signals/cve_not_reachable.js     ← never required
//   signals/cwe_not_reachable.js     ← never required
//   signals/secret_not_reachable.js  ← never required
//   signals/dlp_not_reachable.js     ← never required
//   signals/ai_not_reachable.js      ← never required
//   signals/malware_not_reachable.js ← never required

const app = express();
app.use(express.json());

app.post('/api/merge', (req, res) => {
    const result = mergeObjects(req.body.base, req.body.override);  // CVE REACHABLE
    const safe   = safeText(req.body.text || '');                   // CVE UNKNOWN (safe path)
    res.json({ result, safe });
});

app.post('/api/render', (req, res) => {
    const html  = renderHtml(req.body.content || '');               // CWE REACHABLE
    const clean = sanitize(req.body.safe || '');                    // CWE UNKNOWN (safe path)
    res.json({ html, clean });
});

app.get('/api/config', (_req, res) => {
    const key    = getApiKey();       // SECRET REACHABLE
    const pubKey = getPublicKey();    // SECRET UNKNOWN (safe path)
    res.json({ key: key.slice(0,4) + '****', pubKey });
});

app.post('/api/user', (req, res) => {
    const tracked = processUserPii(req.body);       // DLP REACHABLE
    const anon    = getAnonProfile(req.body.id);    // DLP UNKNOWN (safe path)
    res.json({ tracked, anon });
});

app.post('/api/llm', async (req, res) => {
    const result = await callLlm(req.body.prompt || '');    // AI REACHABLE
    const caps   = getCapabilities();                        // AI UNKNOWN (safe path)
    res.json({ result, caps });
});

app.listen(4001, () => {
    initBeacon();   // MALWARE REACHABLE
    console.log('signal-matrix-js on 4001');
});
