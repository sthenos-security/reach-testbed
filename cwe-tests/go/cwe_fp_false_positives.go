// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// REACHABLE TEST FILE — CWE FALSE POSITIVE SUPPRESSION CASES
//
// These are TRUE NEGATIVES — semgrep flags them but REACHABLE must suppress.
//
// FP-1: math/rand/v2 import flagged as CWE-327
//   math/rand/v2 is NOT math/rand (v1). v2 removed global state.
//   Using v2 for non-security randomness (timer jitter) is not a vulnerability.
//   Expected: NOT_REACHABLE (suppressed by 5h16 import-line or v2 detection)
//
// FP-2: exec.Command with validated path (CWE-78)
//   exec.Command receives a path but content is validated via validateScript()
//   before execution. Path is not user HTTP input — managed directory only.
//   Expected: NOT_REACHABLE
// ============================================================================
package main

import (
	"context"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ─── FP-1: math/rand/v2 for jitter — NOT CWE-327 ────────────────────────────

const renewalThreshold = 180 * 24 * time.Hour

// scheduleRenewal adds random jitter to prevent thundering herd on cert renewal.
// Uses math/rand/v2 for scheduling only — not a security-sensitive operation.
func scheduleRenewal(certExpiry time.Time, restartFn func(string)) {
	timeUntilExpiry := time.Until(certExpiry)
	renewalTime := timeUntilExpiry - renewalThreshold + time.Minute
	if renewalTime < time.Hour {
		renewalTime = time.Hour
	}
	// Non-security use: jitter to prevent all clients renewing simultaneously
	jitter := time.Duration(mathrand.IntN(int(30 * time.Minute)))
	renewalTime += jitter
	timer := time.NewTimer(renewalTime)
	go func() {
		<-timer.C
		restartFn("certificate renewal")
	}()
}

// ─── FP-2: exec.Command with validated path — NOT CWE-78 ────────────────────

var errInvalidScript = fmt.Errorf("invalid script")

// validateScript checks script content before execution.
// Returns true if script has a valid shebang and can be executed directly.
func validateScript(content string) (bool, error) {
	if len(content) == 0 {
		return false, errInvalidScript
	}
	if !strings.HasPrefix(content, "#!") {
		return false, nil
	}
	firstLine := strings.SplitN(content, "\n", 2)[0]
	if strings.TrimSpace(firstLine) == "#!" {
		return false, errInvalidScript
	}
	return true, nil
}

// execManagedScript executes a script from the managed scripts directory.
// scriptPath is from a trusted managed directory — NOT user HTTP input.
// Content is validated via validateScript() before execution.
// Expected: NOT_REACHABLE (validated path, not user-controlled injection)
func execManagedScript(ctx context.Context, scriptPath string, env []string) ([]byte, int, error) {
	contents, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, -1, fmt.Errorf("reading script: %w", err)
	}
	directExecute, err := validateScript(string(contents))
	if err != nil {
		return nil, -1, fmt.Errorf("validating script: %w", err)
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", scriptPath)
	if directExecute {
		cmd = exec.CommandContext(ctx, scriptPath)
	}
	if env != nil {
		cmd.Env = env
	}
	cmd.Dir = filepath.Dir(scriptPath)
	output, err := cmd.CombinedOutput()
	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return output, exitCode, err
}

func main() {
	scheduleRenewal(time.Now().Add(365*24*time.Hour), func(r string) {
		fmt.Println("restart:", r)
	})
	out, code, err := execManagedScript(context.Background(), "/managed/scripts/healthcheck.sh", nil)
	fmt.Printf("exit=%d err=%v out=%s\n", code, err, out)
}
