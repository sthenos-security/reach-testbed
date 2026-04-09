// Fixture: code_patch · CWE-79 Cross-Site Scripting · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: template_html_type_bypass
// SOURCE: http_request (r.URL.Query)
// SINK: template.HTML (unescaped)
// TAINT_HOPS: 1
// NOTES: template.HTML explicitly marks content as safe HTML — bypasses escaping
package web

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("page").Parse(`<div>{{.Content}}</div>`))

func RenderPage(w http.ResponseWriter, r *http.Request) {
	content := r.URL.Query().Get("content")
	// VULNERABLE: CWE-79 · template.HTML bypasses auto-escaping
	tmpl.Execute(w, map[string]interface{}{
		"Content": template.HTML(content),
	})
}
