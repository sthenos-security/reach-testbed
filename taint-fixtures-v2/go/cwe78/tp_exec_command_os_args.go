// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_cli_args
// SOURCE: cli_args (os.Args)
// SINK: exec.Command
// TAINT_HOPS: 1
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: runner <command>")
		return
	}
	// VULNERABLE: CWE-78 · CLI argument used as command
	out, _ := exec.Command(os.Args[1], os.Args[2:]...).Output()
	fmt.Println(string(out))
}
