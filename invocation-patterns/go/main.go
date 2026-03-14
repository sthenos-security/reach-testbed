// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — All 3 Cases (Go)
//
// Case 1: External endpoint — gin HTTP handlers (REACHABLE)
// Case 2: Internal trigger — goroutines, init(), timers (RA gap)
// Case 3: Dead code — exported functions never called (NOT_REACHABLE)
// ============================================================================
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

// ════════════════════════════════════════════════════════════════════════════
// CASE 1: External Endpoint — REACHABLE + ATTACKER_CONTROLLED
// ════════════════════════════════════════════════════════════════════════════

// Case1SQLi — CWE-89 REACHABLE: HTTP param → SQL
func Case1SQLi(c *gin.Context) {
	name := c.Query("name")
	db, _ := sql.Open("sqlite3", ":memory:")
	// CWE-89 REACHABLE: user input in SQL
	query := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name)
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Case1CmdI — CWE-78 REACHABLE: HTTP param → shell
func Case1CmdI(c *gin.Context) {
	var req struct {
		Cmd string `json:"cmd"`
	}
	c.ShouldBindJSON(&req)
	// CWE-78 REACHABLE: user-controlled command
	out, _ := exec.Command("sh", "-c", req.Cmd).Output()
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}

// Case1PathTraversal — CWE-22 REACHABLE: HTTP param → file read
func Case1PathTraversal(c *gin.Context) {
	filename := c.Query("file")
	// CWE-22 REACHABLE: unsanitized path
	data, _ := os.ReadFile("/var/data/" + filename)
	c.JSON(http.StatusOK, gin.H{"content": string(data)})
}

// ════════════════════════════════════════════════════════════════════════════
// CASE 2: Internal Triggers — REACHABLE (internal) but RA misses them
// ════════════════════════════════════════════════════════════════════════════

// init() — Go's built-in auto-initializer. Runs before main().
// The call graph should detect init() as an entrypoint.
func init() {
	// CWE-78: shell command with constant — runs at program startup
	exec.Command("sh", "-c", "echo 'init telemetry' >> /tmp/go_init.log").Run()
}

// backgroundCleanup — CWE-78 via goroutine launched from main()
func backgroundCleanup() {
	for {
		// CWE-78: shell command with constant — runs every 60s
		exec.Command("sh", "-c", "rm -rf /tmp/expired_go_sessions/*").Run()
		time.Sleep(60 * time.Second)
	}
}

// timedBeacon — CWE-918 C2-like beacon via goroutine
func timedBeacon() {
	for {
		// CWE-918: constant URL, no user input, but suspicious behavior
		http.Get("https://c2-server.attacker.test/checkin")
		time.Sleep(30 * time.Second)
	}
}

// signalDump — CWE-200 triggered by SIGUSR1
func signalDump() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	go func() {
		<-sigs
		// CWE-200: information exposure triggered by signal
		data, _ := os.ReadFile("/etc/passwd")
		os.WriteFile("/tmp/signal_dump.txt", data, 0644)
	}()
}

// ════════════════════════════════════════════════════════════════════════════
// CASE 3: Dead Code — NOT_REACHABLE (never called from anywhere)
// ════════════════════════════════════════════════════════════════════════════

// DeadSQLi — CWE-89 NOT_REACHABLE: exported but never called
func DeadSQLi(db *sql.DB, userInput string) {
	// CWE-89 NOT_REACHABLE: no call path
	query := fmt.Sprintf("DELETE FROM sessions WHERE token='%s'", userInput)
	db.Exec(query)
}

// DeadCmdI — CWE-78 NOT_REACHABLE: exported but never called
func DeadCmdI(cmd string) ([]byte, error) {
	// CWE-78 NOT_REACHABLE: no call path
	return exec.Command("sh", "-c", cmd).Output()
}

// DeadPathTraversal — CWE-22 NOT_REACHABLE: exported but never called
func DeadPathTraversal(filename string) ([]byte, error) {
	// CWE-22 NOT_REACHABLE: no call path
	return os.ReadFile("/var/data/" + filename)
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN — wires Case 1 routes + launches Case 2 goroutines
// ════════════════════════════════════════════════════════════════════════════

func main() {
	// Case 2: launch internal triggers
	go backgroundCleanup()
	go timedBeacon()
	signalDump()

	// Case 1: HTTP routes
	r := gin.Default()
	r.GET("/case1/sqli", Case1SQLi)
	r.POST("/case1/cmdi", Case1CmdI)
	r.GET("/case1/path", Case1PathTraversal)

	r.Run(":5012")
}
