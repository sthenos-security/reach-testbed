// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_env_sourced
// SOURCE: environment (os.Getenv)
// SINK: exec.Command
// TAINT_HOPS: 1
// NOTES: Environment variables are server-controlled, not user-controlled
package builder

import (
	"os"
	"os/exec"
)

func RunBuild() error {
	goPath := os.Getenv("GOPATH")
	// SAFE: command path from environment — server-controlled
	cmd := exec.Command(goPath+"/bin/golangci-lint", "run", "./...")
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
