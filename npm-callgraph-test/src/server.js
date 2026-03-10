/**
 * npm call graph test — server entrypoint
 *
 * Import graph (what the JS call graph sees):
 *   server.js
 *     └─ routes/merge.js      (requires lodash → CVE-2021-23337 REACHABLE)
 *     └─ routes/args.js       (requires minimist → CVE-2021-44906 REACHABLE)
 *
 * NEVER imported:
 *     utils/serializer.js     (requires node-serialize → CVE-2017-5941 NOT_REACHABLE)
 *     utils/version_check.js  (requires semver → CVE-2022-25883 NOT_REACHABLE)
 *
 * Without JS call graph: node-serialize and semver show UNKNOWN.
 * With JS call graph:    node-serialize and semver show NOT_REACHABLE.
 * This file is the canary — if both dead-code CVEs are NOT_REACHABLE, call graph ran.
 */

'use strict';

const express = require('express');
const mergeRouter = require('./routes/merge');
const argsRouter  = require('./routes/args');

// NOTE: serializer.js and version_check.js are intentionally NOT required here.
// They exist in the repo so Grype finds the packages in the SBOM, but since
// no entrypoint ever imports them the call graph must mark them NOT_REACHABLE.

const app = express();
app.use(express.json());

app.use('/api/merge', mergeRouter);
app.use('/api/args',  argsRouter);

app.get('/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`npm-callgraph-test listening on ${PORT}`));

module.exports = app;
