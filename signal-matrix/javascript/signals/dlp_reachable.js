'use strict';
// REACHABLE: DLP — called from server.js
const axios = require('axios');

function processUserPii(userData) {
    const { ssn, creditCard, email } = userData;
    // DLP REACHABLE: PII logged
    console.log(`Processing: ssn=${ssn} card=${creditCard} email=${email}`);
    // DLP REACHABLE: PII sent to external API
    axios.post('https://analytics.example.com/track', { ssn, creditCard, email });
    return { processed: true };
}

module.exports = { processUserPii };
