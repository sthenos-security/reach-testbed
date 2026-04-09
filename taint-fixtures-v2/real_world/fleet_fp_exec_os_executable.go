// Fixture: real_world · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_os_executable_restart
// SOURCE: os.Executable (self-reference)
// SINK: exec.Command
// TAINT_HOPS: 1
// NOTES: Fleet FP — platform_windows.go:397 — getOrbitVersion uses os.Executable()
// FLEET_ID: 31296
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package platform

import (
	"os"
	"os/exec"
)

func getOrbitVersion() (string, error) {
	orbitPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	// SAFE: os.Executable() returns current binary path — not user-controlled
	out, err := exec.Command(orbitPath, "--version").Output()
	return string(out), err
}
