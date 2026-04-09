// Fixture: CWE-918 SSRF - TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: hardcoded_api_endpoint
// SOURCE: none (literal)
// SINK: fetch
// TAINT_HOPS: 0
// NOTES: Hardcoded API endpoint - no user control over URL

const API_URL = 'https://api.openai.com';

export async function callModelSafe(prompt: string): Promise<string> {
    // SAFE: endpoint is hardcoded
    const response = await fetch(`${API_URL}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
    });
    return (await response.json()).text;
}
