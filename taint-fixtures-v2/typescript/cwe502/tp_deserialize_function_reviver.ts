// Fixture: CWE-502 Deserialization - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: json_parse_with_function_reconstruction
// SOURCE: http_request
// SINK: new Function
// TAINT_HOPS: 2
// NOTES: JSON.parse reviver reconstructs functions from untrusted data
export function deserialize(data: string): any {
    return JSON.parse(data, (key, value) => {
        if (typeof value === 'string' && value.startsWith('__fn:')) {
            // VULNERABLE: reconstructing functions from untrusted serialized data
            return new Function('return ' + value.slice(5))();
        }
        return value;
    });
}
