// Fixture: real_world · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_fixed_string_no_user_input
// SOURCE: none (literal string)
// SINK: exec.Command
// TAINT_HOPS: 0
// NOTES: Fleet FP — main.go:159 — fixed command string with no user-controlled input
// FLEET_ID: 31484
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package osqueryopts

import "os/exec"

func runFixedCommand() error {
	// SAFE: command is a fixed string with no user-controlled input
	// Fleet scanner flagged: "Detected non-static command inside Command"
	return exec.Command("osqueryi", "--version").Run()
}
