/**
 * REACHABLE: lodash CVE-2021-23337 (prototype pollution via _.merge)
 *
 * Call path:
 *   server.js → require('./routes/merge') → _.merge()
 *
 * Attacker payload: { "__proto__": { "admin": true } }
 * lodash 4.17.20 does not guard against prototype pollution in _.merge.
 */

'use strict';

const express = require('express');
const _ = require('lodash');   // CVE-2021-23337 — imported AND called below

const router = express.Router();

router.post('/', (req, res) => {
    const { base = {}, override = {} } = req.body;

    // CVE-2021-23337: _.merge does not sanitize __proto__ keys.
    // This is the live code path — call graph must mark lodash REACHABLE.
    const result = _.merge({}, base, override);

    res.json({ result });
});

module.exports = router;
