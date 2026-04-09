// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: innerhtml_direct_user_content
// SOURCE: function_parameter
// SINK: element.innerHTML
// TAINT_HOPS: 1
// NOTES: Direct user HTML to innerHTML — classic XSS
// REAL_WORLD: microsoft/vscode src/vs/workbench/contrib/webview/browser
export function displayWebviewContent(htmlContent: string): void {
    const el = document.getElementById('webview')!;
    // VULNERABLE: direct assignment of user HTML
    el.innerHTML = htmlContent;
}
