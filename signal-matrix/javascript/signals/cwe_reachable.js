'use strict';
// REACHABLE: CWE — called from server.js
function renderHtml(content) {
    // CWE-79: XSS — user input directly in innerHTML equivalent
    return `<div>${content}</div>`; // REACHABLE: unsanitized interpolation
}
module.exports = { renderHtml };
