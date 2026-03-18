// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — Case 4: Dynamic Invocation (Go)
//
// Tests patterns where static call graph misses function reachability because
// the function reference is computed at runtime via reflection, function
// values, maps, or interface dispatch.
//
// Each case is annotated with:
//   REACH: expected reachability state
//   CG:    whether static CG catches it (YES / NO / PARTIAL)
//   WHY:   root cause if static CG misses
// ============================================================================
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"plugin"
	"reflect"

	"github.com/gin-gonic/gin"
)

// ── CASE 1: Function value stored in map ───────────────────────────────────
// REACH: REACHABLE   CG: PARTIAL   CONFIDENCE: MEDIUM
// CG should trace map literal values as reachable; which one runs is PARTIAL.

func dynCreateUser(name string) string {
	// CWE-89: SQL injection via map-dispatched function
	return fmt.Sprintf("INSERT INTO users (name) VALUES ('%s')", name) // CWE-89 REACHABLE
}

func dynDeleteUser(id string) string {
	// CWE-89: SQL injection via map-dispatched function
	return fmt.Sprintf("DELETE FROM users WHERE id=%s", id) // CWE-89 REACHABLE
}

var dispatchMap = map[string]func(string) string{
	"create": dynCreateUser,
	"delete": dynDeleteUser,
}

func DynDispatch(c *gin.Context) {
	action := c.Query("action")
	value := c.Query("value")
	if fn, ok := dispatchMap[action]; ok {
		result := fn(value) // CG: PARTIAL — must trace map literal fn values
		c.JSON(http.StatusOK, gin.H{"result": result})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
}

// ── CASE 2: reflect.Value.Call() ───────────────────────────────────────────
// REACH: UNKNOWN   CG: NO   CONFIDENCE: LOW
// Function resolved at runtime via reflection — CG cannot determine callee.

func sensitiveOp(input string) {
	// CWE-78: called via reflect.Value.Call() with runtime method name
	exec.Command("sh", "-c", "log "+input).Run() // CWE-78 UNKNOWN
}

func DynReflect(c *gin.Context) {
	methodName := c.Query("method")
	// CWE-78 UNKNOWN: which function is called depends on runtime string
	fn := reflect.ValueOf(sensitiveOp)
	if fn.IsValid() && methodName == "sensitiveOp" {
		fn.Call([]reflect.Value{reflect.ValueOf(c.Query("input"))})
	}
	c.JSON(http.StatusOK, gin.H{"status": "called"})
}

// ── CASE 3: Interface dispatch ─────────────────────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: MEDIUM
// CG should trace all implementors of the interface as potentially reachable.

type Handler interface {
	Handle(input string) string
}

type SqlHandler struct{}

func (h SqlHandler) Handle(input string) string {
	// CWE-89: SQL injection via interface method
	return fmt.Sprintf("SELECT * FROM logs WHERE user='%s'", input) // CWE-89 REACHABLE
}

type CmdHandler struct{}

func (h CmdHandler) Handle(input string) string {
	// CWE-78: OS command via interface method
	out, _ := exec.Command("sh", "-c", "echo "+input).Output() // CWE-78 REACHABLE
	return string(out)
}

func DynInterface(c *gin.Context) {
	input := c.Query("input")
	handlerType := c.Query("type")

	var h Handler
	if handlerType == "sql" {
		h = SqlHandler{}
	} else {
		h = CmdHandler{}
	}
	result := h.Handle(input) // CG: should trace all Handler implementors
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ── CASE 4: goroutine with function variable ────────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
// CG should trace fn inside go fn() as reachable.

func goroutineTask(cmd string) {
	// CWE-78: OS command executed in goroutine
	exec.Command("sh", "-c", cmd).Run() // CWE-78 REACHABLE
}

func DynGoroutine(c *gin.Context) {
	cmd := c.Query("cmd")
	fn := goroutineTask
	go fn(cmd) // CG should trace fn → goroutineTask as reachable
	c.JSON(http.StatusOK, gin.H{"status": "launched"})
}

// ── CASE 5: plugin.Open() — runtime-loaded .so ────────────────────────────
// REACH: UNKNOWN   CG: NO   CONFIDENCE: LOW
// Plugin path determined at runtime — CG cannot analyze the loaded code.

func DynPlugin(c *gin.Context) {
	pluginPath := c.Query("plugin")
	// CWE-829: Uncontrolled inclusion of functionality at runtime
	p, err := plugin.Open(pluginPath) // CWE-829 UNKNOWN
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sym, err := p.Lookup("Run")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if fn, ok := sym.(func() string); ok {
		c.JSON(http.StatusOK, gin.H{"result": fn()})
	}
}

// ── CASE 6: http.HandlerFunc passed as variable ────────────────────────────
// REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH

func pathTraversalHandler(w http.ResponseWriter, r *http.Request) {
	// CWE-22: path traversal via http.HandlerFunc variable
	filename := r.URL.Query().Get("file")
	data, _ := os.ReadFile("/var/data/" + filename) // CWE-22 REACHABLE
	w.Write(data)
}

func DynHandlerFunc(c *gin.Context) {
	// Wraps a handler func in a variable and registers it
	fn := http.HandlerFunc(pathTraversalHandler)
	fn.ServeHTTP(c.Writer, c.Request) // CG should trace pathTraversalHandler as reachable
}

// ── CASE 7: Dead code — function value never assigned to anything ──────────
// REACH: NOT_REACHABLE   CG: YES

func deadDynHandler(input string) string {
	// CWE-89: never placed in any map, passed to any goroutine, or called
	return fmt.Sprintf("DROP TABLE %s", input) // CWE-89 NOT_REACHABLE
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN — registers dynamic invocation routes
// ════════════════════════════════════════════════════════════════════════════

func init() {
	// ensure deadDynHandler reference exists for compiler (never actually called)
	_ = deadDynHandler
}

func RegisterDynamicRoutes(r *gin.Engine) {
	r.GET("/dynamic/dispatch", DynDispatch)
	r.GET("/dynamic/reflect", DynReflect)
	r.GET("/dynamic/interface", DynInterface)
	r.GET("/dynamic/goroutine", DynGoroutine)
	r.GET("/dynamic/plugin", DynPlugin)
	r.GET("/dynamic/handler-func", DynHandlerFunc)
}
