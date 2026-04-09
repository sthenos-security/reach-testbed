// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_shell_wrapper_concat
// SOURCE: http_request (r.URL.Query)
// SINK: exec.Command via sh -c
// TAINT_HOPS: 1
package scanner

import (
	"net/http"
	"os/exec"
)

func RunShellCommand(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	// VULNERABLE: CWE-78 · shell wrapper with string concatenation
	out, _ := exec.Command("sh", "-c", "nmap -sV "+target).Output()
	w.Write(out)
}
