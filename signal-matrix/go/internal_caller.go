package main

/*
Internal Caller — proves exported functions become REACHABLE when called.

This file imports and calls the exported "Dead" functions from the signals
package. Since main.go calls InternalCaller() and InternalCaller() calls
the exported functions, the call chain is:

  main → InternalCaller → PathTraversalDead      → REACHABLE
  main → InternalCaller → GetAwsCredsDead         → REACHABLE
  main → InternalCaller → LogPiiDead              → REACHABLE
  main → InternalCaller → CallLlmWithPiiDead      → REACHABLE
  main → InternalCaller → ExfilDead               → REACHABLE

This validates Level 3 of the 3-level reachability model:
  Level 1: package EXISTS (go.mod)
  Level 2: package IMPORTED (main.go imports signals)
  Level 3: function CALLED (this file calls them from a reachable path)
*/

import (
	"fmt"

	"github.com/sthenos/signal-matrix-go/signals"
)

// InternalCaller exercises exported functions that would otherwise be UNKNOWN.
// Called from main.go to make the full chain reachable.
func InternalCaller() {
	// CWE — PathTraversalDead is now REACHABLE via this call chain
	data, err := signals.PathTraversalDead("../../etc/passwd")
	if err != nil {
		fmt.Println("path traversal:", err)
	}
	_ = data

	// SECRET — GetAwsCredsDead is now REACHABLE
	signals.GetAwsCredsDead()

	// DLP — LogPiiDead is now REACHABLE
	signals.LogPiiDead("123-45-6789", "4111-1111-1111-1111", "patient@example.com")

	// AI — CallLlmWithPiiDead is now REACHABLE
	signals.CallLlmWithPiiDead("123-45-6789", "diabetes type 2")

	// MALWARE — ExfilDead is now REACHABLE
	signals.ExfilDead()
}
