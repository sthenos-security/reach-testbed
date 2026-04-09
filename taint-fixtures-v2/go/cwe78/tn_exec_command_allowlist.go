// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_allowlist_guard
// SOURCE: http_request (r.URL.Query)
// SINK: exec.Command
// TAINT_HOPS: 1
// NOTES: User input validated against allowlist before use
package scanner

import (
	"fmt"
	"net/http"
	"os/exec"
)

var allowedTools = map[string]bool{
	"nmap": true, "dig": true, "ping": true,
}

func RunTool(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	if !allowedTools[tool] {
		http.Error(w, "tool not allowed", http.StatusForbidden)
		return
	}
	// SAFE: tool validated against allowlist
	out, _ := exec.Command(tool, r.URL.Query().Get("target")).Output()
	w.Write(out)
	fmt.Fprintln(w)
}
