// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_constant_binary_path
// SOURCE: none (constant)
// SINK: exec.Command
// TAINT_HOPS: 0
// NOTES: Hardcoded system binary path — Fleet FP pattern (main.go:112)
package health

import "os/exec"

const fleetctlPath = "/usr/local/bin/fleetctl"

func CheckFleetHealth() (string, error) {
	// SAFE: constant binary path with literal arguments
	out, err := exec.Command(fleetctlPath, "get", "hosts", "--json").Output()
	return string(out), err
}
