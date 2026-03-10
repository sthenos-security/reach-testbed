'use strict';
// NOT_REACHABLE: DLP — file NEVER required
const SSN_HARDCODED  = '078-05-1120';        // NR
const CARD_HARDCODED = '4532015112830366';   // NR

function sendPiiToLlmDead(patient) {
    const axios = require('axios');
    // DLP NOT_REACHABLE: PII → LLM API
    axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4',
        messages: [{ role: 'user', content: `ssn=${patient.ssn} dob=${patient.dob}` }]
    });
}

function logPiiDead(user) {
    console.log(`ssn=${user.ssn} card=${user.creditCard} email=${user.email}`);
}
