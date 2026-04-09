// Fixture: real_world · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_hardcoded_binary_path
// SOURCE: none (constant path)
// SINK: exec.Command
// TAINT_HOPS: 0
// NOTES: Fleet FP — main.go:112 — hardcoded path to osqueryd binary
// FLEET_ID: 31483
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package osqueryopts

import (
	"os/exec"
)

const osquerydPath = "/usr/local/bin/osqueryd"

func main() {
	// SAFE: hardcoded binary path with literal arguments
	// Fleet scanner flagged this as CWE-78 — should be suppressed
	cmd := exec.Command(osquerydPath, "-S", "--json")
	cmd.Run()
}
