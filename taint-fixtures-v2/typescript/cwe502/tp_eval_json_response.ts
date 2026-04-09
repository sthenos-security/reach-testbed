// Fixture: CWE-502 Deserialization - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: eval_json_response
// SOURCE: http_request
// SINK: eval
// TAINT_HOPS: 1
// NOTES: Using eval() to parse JSON from untrusted source - RCE
export function parseResponse(body: string): any {
    // VULNERABLE: eval can execute arbitrary code, not just parse JSON
    return eval('(' + body + ')');
}
