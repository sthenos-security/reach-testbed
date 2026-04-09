// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_user_controlled_binary
// SOURCE: http_request (r.URL.Query)
// SINK: exec.Command
// TAINT_HOPS: 1
package scanner

import (
	"net/http"
	"os/exec"
)

func RunUserCommand(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// VULNERABLE: CWE-78 · user-controlled binary path
	out, _ := exec.Command(cmd).Output()
	w.Write(out)
}
