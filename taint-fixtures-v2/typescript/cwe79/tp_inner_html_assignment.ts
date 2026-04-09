// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: dom_inner_html_user_input
// SOURCE: url_params (URLSearchParams)
// SINK: innerHTML assignment
// TAINT_HOPS: 1

// VULNERABLE: CWE-79 · innerHTML set from URL parameter
const params = new URLSearchParams(window.location.search);
const name = params.get('name') || '';
document.getElementById('greeting')!.innerHTML = `<h1>Hello, ${name}!</h1>`;
