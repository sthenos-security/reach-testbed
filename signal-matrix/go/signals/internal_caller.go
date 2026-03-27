package signals

// InternalCaller bridges main → Dead functions for Level 3 reachability testing.
// main() calls InternalCaller(), which calls *Dead() functions.
// This tests that BFS can trace multi-hop internal call chains.

func InternalCaller() {
	PathTraversalDead()
	GetAwsCredsDead()
	LogPiiDead()
	CallLlmWithPiiDead()
	ExfilDead()
}
