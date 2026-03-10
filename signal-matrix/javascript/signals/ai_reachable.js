'use strict';
// REACHABLE: AI — called from server.js
const axios = require('axios');

async function callLlm(userPrompt) {
    // LLM01 REACHABLE: unsanitized user input to OpenAI
    const resp = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4',
        messages: [{ role: 'user', content: userPrompt }]  // VIOLATION: unsanitized
    }, { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });
    return resp.data.choices[0].message.content;
}

module.exports = { callLlm };
