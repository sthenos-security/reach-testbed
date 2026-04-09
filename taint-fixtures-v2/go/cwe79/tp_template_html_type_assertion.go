// Fixture: CWE-79 Cross-Site Scripting - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: template_html_type_bypass_autoescape
// SOURCE: function_parameter (user content)
// SINK: template.HTML type conversion
// TAINT_HOPS: 1
// NOTES: template.HTML() marks string as safe HTML, bypassing html/template auto-escaping
// REAL_WORLD: grafana/grafana, kubernetes dashboard patterns
package web

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("page").Parse("{{.Content}}"))

func RenderUserContent(w http.ResponseWriter, r *http.Request) {
	content := r.URL.Query().Get("content")
	// VULNERABLE: template.HTML() tells the template engine this is pre-sanitized
	// but it comes directly from user input
	data := struct{ Content template.HTML }{Content: template.HTML(content)}
	tmpl.Execute(w, data)
}
