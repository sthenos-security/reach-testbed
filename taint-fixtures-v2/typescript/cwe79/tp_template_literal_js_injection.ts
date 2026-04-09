// Fixture: CWE-79 Cross-Site Scripting - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: template_literal_in_generated_javascript
// SOURCE: function_parameter (URI)
// SINK: inline script generation
// TAINT_HOPS: 1
// NOTES: URI interpolated into generated JavaScript - allows javascript: protocol XSS
// REAL_WORLD: microsoft/vscode src/vs/workbench/api/node/loopbackServer.ts
function generateRedirectPage(appUri: string): string {
    // VULNERABLE: appUri could be javascript:alert(1) - executes in browser context
    return `<html><body><script>window.location.href = '${appUri}';</script></body></html>`;
}
