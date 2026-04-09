// Fixture: real_world · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_bash_with_variable
// SOURCE: function_parameter (cmd string)
// SINK: exec.Command via bash -c
// TAINT_HOPS: 1
// NOTES: Fleet TP — cli.go:13 — RunCommandAndReturnOutput passes variable to bash
// FLEET_ID: 31474
// AI_VERDICT: TRUE_POSITIVE · sev=CRITICAL · conf=HIGH
package ghapi

import (
	"os/exec"
)

func RunCommandAndReturnOutput(cmd string) (string, error) {
	// VULNERABLE: CWE-78 · variable command passed to bash shell
	out, err := exec.Command("bash", "-c", cmd).Output()
	return string(out), err
}
