// Fixture: code_patch · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_stdin_input
// SOURCE: stdin (bufio.Scanner)
// SINK: exec.Command via sh -c
// TAINT_HOPS: 1
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter command: ")
	scanner.Scan()
	userCmd := scanner.Text()
	// VULNERABLE: CWE-78 · stdin input passed to shell
	out, _ := exec.Command("sh", "-c", userCmd).Output()
	fmt.Println(string(out))
}
