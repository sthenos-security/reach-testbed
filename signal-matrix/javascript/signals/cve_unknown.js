'use strict';
/**
 * UNKNOWN: CVE — module required, safe export called, vulnerable function never invoked.
 * marked 4.0.10 is required here but parseMarkdownUnknown() is never called from server.js.
 * CVE-2022-21681: marked ReDoS via crafted markdown input.
 */
const marked = require('marked'); // CVE-2022-21681

/** Safe export — called from server.js. No CVE path. */
function safeText(text) {
    return text.replace(/[<>]/g, '');
}

/**
 * CVE UNKNOWN: marked.parse() called with user input.
 * Module IS required but this function has no call path from server.js.
 */
function parseMarkdownUnknown(userMarkdown) {
    return marked.parse(userMarkdown); // CVE-2022-21681 trigger
}

module.exports = { safeText, parseMarkdownUnknown };
