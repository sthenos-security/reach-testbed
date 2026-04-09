// Fixture: CWE-79 Cross-Site Scripting - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: responsewriter_sprintf_html
// SOURCE: http_request query
// SINK: fmt.Fprintf to ResponseWriter
// TAINT_HOPS: 1
// NOTES: User input written directly to HTTP response as HTML
package web

import (
	"fmt"
	"net/http"
)

func SearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: user input reflected in HTML response
	fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", query)
}
