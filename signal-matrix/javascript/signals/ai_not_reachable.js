'use strict';
// NOT_REACHABLE: AI — file NEVER required
const axios = require('axios');

async function promptInjectionDead(userInput) {
    // LLM01 NOT_REACHABLE
    const resp = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4',
        messages: [{ role: 'user', content: userInput }]
    });
    return eval(resp.data.choices[0].message.content); // LLM05 too: eval LLM output
}

async function piiToLlmDead(patient) {
    // AI + DLP NOT_REACHABLE
    await axios.post('https://api.openai.com/v1/chat/completions', {
        messages: [{ role: 'user', content: `ssn=${patient.ssn} diagnosis=${patient.diagnosis}` }]
    });
}
