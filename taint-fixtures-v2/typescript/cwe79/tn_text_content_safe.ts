// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: dom_text_content_safe
// SOURCE: url_params (URLSearchParams)
// SINK: textContent (safe — text only)
// TAINT_HOPS: 1
// NOTES: textContent does not parse HTML — always safe

// SAFE: textContent sets plain text, not HTML
const params = new URLSearchParams(window.location.search);
const name = params.get('name') || '';
document.getElementById('greeting')!.textContent = `Hello, ${name}!`;
