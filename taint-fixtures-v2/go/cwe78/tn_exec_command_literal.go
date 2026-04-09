// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_fully_literal
// SOURCE: none (literal strings)
// SINK: exec.Command
// TAINT_HOPS: 0
// NOTES: All arguments are string literals — no user input
package scanner

import "os/exec"

func ListFiles() (string, error) {
	// SAFE: fully literal command and arguments
	out, err := exec.Command("ls", "-la", "/tmp").Output()
	return string(out), err
}
