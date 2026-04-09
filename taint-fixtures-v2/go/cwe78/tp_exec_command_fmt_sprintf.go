// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_shell_wrapper_sprintf
// SOURCE: http_request (r.FormValue)
// SINK: exec.Command via bash -c
// TAINT_HOPS: 1
package scanner

import (
	"fmt"
	"net/http"
	"os/exec"
)

func RunFormattedCommand(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// VULNERABLE: CWE-78 · fmt.Sprintf builds shell command with user input
	cmd := fmt.Sprintf("ping -c 3 %s", host)
	out, _ := exec.Command("bash", "-c", cmd).Output()
	w.Write(out)
}
