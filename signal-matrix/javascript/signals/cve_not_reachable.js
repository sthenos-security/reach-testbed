'use strict';
// NOT_REACHABLE: CVE — file NEVER required by server.js
const serialize = require('node-serialize'); // CVE-2017-5941

function deserialize(raw) {
    return serialize.unserialize(raw); // RCE via eval — NOT_REACHABLE
}

// Not exported to reinforce isolation
