// Fixture: real_world · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_static_binary_system_info
// SOURCE: none (static binary call)
// SINK: exec.Command
// TAINT_HOPS: 0
// NOTES: Fleet FP — orbit.go:2059 — getHostInfo calls a static system binary
// FLEET_ID: 31281
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package orbit

import (
	"os/exec"
)

func getHostInfo() (string, error) {
	// SAFE: static system command to gather host information
	// No user input reaches this call — command is entirely server-controlled
	out, err := exec.Command("hostname", "-f").Output()
	return string(out), err
}
