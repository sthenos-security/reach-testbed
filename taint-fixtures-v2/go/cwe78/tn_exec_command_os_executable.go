// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_self_executable
// SOURCE: os.Executable (self-reference)
// SINK: exec.Command
// TAINT_HOPS: 1
// NOTES: os.Executable returns path to current binary — server-controlled
package updater

import (
	"os"
	"os/exec"
)

func RestartSelf() error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}
	// SAFE: executing self — os.Executable is not user-controlled
	cmd := exec.Command(selfPath, "--restart")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}
