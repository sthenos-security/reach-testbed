// Fixture: code_patch · CWE-79 Cross-Site Scripting · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: fmt_fprintf_raw_html
// SOURCE: http_request (r.URL.Query)
// SINK: fmt.Fprintf (raw HTML output)
// TAINT_HOPS: 1
package web

import (
	"fmt"
	"net/http"
)

func GreetUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: CWE-79 · raw HTML output with user input
	fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
}
