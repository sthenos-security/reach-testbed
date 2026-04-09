// Fixture: real_world · CWE-78 Command Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_user_controlled_via_parameter
// SOURCE: function_parameter (cmd string)
// SINK: exec.Command
// TAINT_HOPS: 1
// NOTES: Fleet TP — exec.go:36 — Exec() receives user-controlled command via parameter
// FLEET_ID: 31305
// AI_VERDICT: TRUE_POSITIVE · sev=CRITICAL · conf=HIGH
package tablehelpers

import (
	"context"
	"os/exec"
	"time"
)

func Exec(ctx context.Context, timeout time.Duration, cmd string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// VULNERABLE: CWE-78 · cmd parameter is passed from caller — may be user-controlled
	return exec.CommandContext(ctx, cmd, args...).Output()
}
