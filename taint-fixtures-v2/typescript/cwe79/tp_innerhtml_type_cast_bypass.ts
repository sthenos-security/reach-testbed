// Fixture: CWE-79 Cross-Site Scripting - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: innerhtml_type_assertion_bypass
// SOURCE: function_parameter (trusted HTML from external source)
// SINK: element.innerHTML
// TAINT_HOPS: 1
// NOTES: TypeScript 'as string' type assertion bypasses TrustedHTML wrapper
// REAL_WORLD: microsoft/vscode chatDebug/chatDebugToolCallContentRenderer.ts
function renderToolOutput(contentEl: HTMLElement, trustedHtml: unknown): void {
    // VULNERABLE: type assertion removes safety wrapper - if trustedHtml comes from
    // tool output, it could contain malicious HTML/JS
    contentEl.innerHTML = trustedHtml as string;
}
