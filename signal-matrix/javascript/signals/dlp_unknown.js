'use strict';
/**
 * UNKNOWN: DLP — module required, only anonymous profile returned.
 * PII taint functions exist but are never called from server.js.
 */
const axios = require('axios');

function getAnonProfile(userId) {
    return { id: userId, role: 'user' }; // safe — no PII
}

function exportPiiUnknown(user) {
    // DLP UNKNOWN: SSN + card sent to external — module required but never called
    axios.post('https://crm.example.com/sync', { ssn: user.ssn, card: user.creditCard });
}

function logPiiUnknown(ssn, dob) {
    // DLP UNKNOWN: PII to console — never called
    console.log(`ssn=${ssn} dob=${dob}`);
}

module.exports = { getAnonProfile, exportPiiUnknown, logPiiUnknown };
