// Fixture: CWE-918 SSRF - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: ssrf_user_controlled_baseurl
// SOURCE: config_parameter
// SINK: fetch
// TAINT_HOPS: 1
// NOTES: OpenAI/Anthropic SDK-style custom baseURL from config
// REAL_WORLD: openai/openai-node custom endpoint pattern

export async function callModel(baseURL: string, prompt: string): Promise<string> {
    // VULNERABLE: baseURL could point to internal services (169.254.169.254)
    const response = await fetch(`${baseURL}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
    });
    return (await response.json()).text;
}
