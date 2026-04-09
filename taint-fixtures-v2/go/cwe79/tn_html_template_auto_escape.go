// Fixture: code_patch · CWE-79 Cross-Site Scripting · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: html_template_auto_escape
// SOURCE: http_request (r.URL.Query)
// SINK: template.Execute (auto-escaped)
// TAINT_HOPS: 1
// NOTES: html/template auto-escapes by default — safe unless bypassed
package web

import (
	"html/template"
	"net/http"
)

var safeTmpl = template.Must(template.New("page").Parse(`<div>{{.Content}}</div>`))

func RenderPageSafe(w http.ResponseWriter, r *http.Request) {
	content := r.URL.Query().Get("content")
	// SAFE: html/template auto-escapes string values
	safeTmpl.Execute(w, map[string]interface{}{
		"Content": content,
	})
}
