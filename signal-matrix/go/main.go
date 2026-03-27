package main

/*
Signal Matrix — Go entrypoint

Import graph determines reachability:
  REACHABLE  — package imported AND vulnerable function called from a handler
  UNKNOWN    — package imported, only safe function called; vuln func exists but not on call path
  NOT_REACHABLE — package used in a function that is never called (dead code)

Signals covered: CVE, CWE, SECRET, DLP, AI, MALWARE
*/

import (
	"github.com/gin-gonic/gin"

	"github.com/sthenos/signal-matrix-go/signals"
)

func main() {
	r := gin.Default()

	// CVE REACHABLE
	r.POST("/api/translate", signals.TranslateHandler)
	// CWE REACHABLE
	r.POST("/api/query",   signals.QueryHandler)
	r.POST("/api/cmd",     signals.CmdHandler)
	// SECRET REACHABLE: called in handler
	r.GET("/api/config",   signals.ConfigHandler)
	// DLP REACHABLE
	r.POST("/api/patient", signals.PatientHandler)
	// AI REACHABLE
	r.POST("/api/llm",     signals.LlmHandler)

	// UNKNOWN: package imported but only safe function called
	r.GET("/api/health",   signals.HealthHandler) // calls signals.SafeVersion() internally

	// MALWARE REACHABLE — beacon on startup
	signals.InitBeacon()

	// Level 3: internal caller bridges to Dead functions
	signals.InternalCaller()

	r.Run(":8082")
}
