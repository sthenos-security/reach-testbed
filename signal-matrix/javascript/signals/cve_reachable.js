'use strict';
// REACHABLE: CVE — required and called from server.js
const _ = require('lodash'); // CVE-2021-23337

function mergeObjects(base = {}, override = {}) {
    return _.merge({}, base, override); // REACHABLE: prototype pollution path
}

module.exports = { mergeObjects };
