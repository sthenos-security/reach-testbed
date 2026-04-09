// Fixture: CWE-502 Deserialization - TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: json_parse_typed
// SOURCE: http_request
// SINK: JSON.parse
// TAINT_HOPS: 1
// NOTES: JSON.parse into typed interface - no code execution
interface UserData {
    name: string;
    email: string;
}

export function parseUser(body: string): UserData {
    // SAFE: JSON.parse only produces data, no code execution
    const data: UserData = JSON.parse(body);
    return data;
}
