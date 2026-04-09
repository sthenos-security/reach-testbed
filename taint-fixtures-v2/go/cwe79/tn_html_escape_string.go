// Fixture: code_patch · CWE-79 Cross-Site Scripting · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: html_escape_string_sanitized
// SOURCE: http_request (r.URL.Query)
// SINK: fmt.Fprintf (escaped output)
// TAINT_HOPS: 1
// NOTES: html.EscapeString sanitizes HTML special characters
package web

import (
	"fmt"
	"html"
	"net/http"
)

func GreetUserSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	// SAFE: html.EscapeString sanitizes HTML special characters
	fmt.Fprintf(w, "<h1>Hello, %s!</h1>", html.EscapeString(name))
}
