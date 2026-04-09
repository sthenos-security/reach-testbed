// Fixture: CWE-79 Cross-Site Scripting - Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: html_template_contextual_escape
// SOURCE: http_request query
// SINK: html/template.Execute
// TAINT_HOPS: 1
// NOTES: html/template provides contextual auto-escaping - safe
package web

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("search").Parse(
	"<html><body>Results for: {{.Query}}</body></html>"))

func SearchHandlerSafe(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	data := struct{ Query string }{Query: query}
	// SAFE: html/template auto-escapes based on context
	tmpl.Execute(w, data)
}
