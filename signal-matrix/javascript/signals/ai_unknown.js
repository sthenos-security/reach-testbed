'use strict';
/**
 * UNKNOWN: AI — module required, only capabilities metadata returned.
 * LLM calls exist in this module but are never invoked from server.js.
 */
const axios = require('axios');

function getCapabilities() {
    return { model: 'gpt-4', maxTokens: 4096 }; // safe — no LLM call
}

async function runUncheckedLlmUnknown(userPrompt) {
    // LLM01 UNKNOWN: user input to LLM, module required but never called
    const resp = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4',
        messages: [{ role: 'user', content: userPrompt }]
    });
    return resp.data.choices[0].message.content;
}

function evalLlmOutputUnknown(llmCode) {
    // LLM05 UNKNOWN: eval(LLM output), never called
    return eval(llmCode);
}

module.exports = { getCapabilities, runUncheckedLlmUnknown, evalLlmOutputUnknown };
