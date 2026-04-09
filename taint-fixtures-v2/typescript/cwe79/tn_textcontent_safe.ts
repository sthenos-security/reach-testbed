// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: textcontent_auto_escapes
// SOURCE: function_parameter
// SINK: element.textContent
// TAINT_HOPS: 1
// NOTES: textContent auto-escapes HTML — always safe
// REAL_WORLD: microsoft/vscode src/vs/workbench/browser/parts/editor/editorStatusBar.ts
export function updateStatusBar(ln: number, col: number): void {
    const el = document.querySelector('.editor-status')!;
    el.textContent = `Ln ${ln}, Col ${col}`;
}
