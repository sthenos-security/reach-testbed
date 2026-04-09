// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_shell_wrapper_literal
// SOURCE: none (literal string)
// SINK: exec.Command via sh -c
// TAINT_HOPS: 0
// NOTES: Shell wrapper but command is fully literal — no user input
package scanner

import "os/exec"

func RestartService() error {
	// SAFE: shell wrapper with fully literal command
	return exec.Command("sh", "-c", "systemctl restart nginx").Run()
}
