// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_user_as_argument_no_shell
// SOURCE: http_request (r.URL.Query)
// SINK: exec.Command (no shell wrapper)
// TAINT_HOPS: 1
// NOTES: User input passed as argument to fixed binary — no shell interpretation
package scanner

import (
	"net/http"
	"os/exec"
)

func LookupHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// SAFE: fixed binary with user input as argument, no shell wrapper
	out, _ := exec.Command("dig", "+short", host).Output()
	w.Write(out)
}
