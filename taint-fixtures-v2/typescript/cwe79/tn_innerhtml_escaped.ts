// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: innerhtml_html_escaped
// SOURCE: function_parameter
// SINK: element.innerHTML
// TAINT_HOPS: 1
// NOTES: VSCode-style — content HTML-escaped before innerHTML assignment
// REAL_WORLD: microsoft/vscode src/vs/workbench/browser/parts/notifications
function escapeHtml(t: string): string {
    return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

export function showNotification(message: string): void {
    const el = document.querySelector('#notification-center')!;
    const safe = escapeHtml(message);
    el.innerHTML = `<div class="notification"><p>${safe}</p></div>`;
}
