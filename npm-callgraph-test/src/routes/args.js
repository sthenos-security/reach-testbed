/**
 * REACHABLE: minimist CVE-2021-44906 (prototype pollution via __proto__)
 *
 * Call path:
 *   server.js → require('./routes/args') → minimist(argv)
 *
 * minimist 1.2.5 allows __proto__ pollution when parsing CLI args.
 */

'use strict';

const express = require('express');
const minimist = require('minimist');  // CVE-2021-44906 — imported AND called below

const router = express.Router();

router.post('/', (req, res) => {
    const rawArgs = req.body.args || [];

    // CVE-2021-44906: minimist does not filter __proto__ from parsed args.
    // Live code path — call graph must mark minimist REACHABLE.
    const parsed = minimist(rawArgs);

    res.json({ parsed });
});

module.exports = router;
