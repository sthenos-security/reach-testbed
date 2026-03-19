// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
// Framework: Echo (Go)
//
// CWE-89  SQL Injection
// CWE-78  OS Command Injection
// CWE-22  Path Traversal
// CWE-918 SSRF
//
// Echo entrypoint model (different from Gin):
//   e.GET(path, handler)        — direct registration
//   e.Group(prefix)             — route group, all sub-routes REACHABLE
//   e.Use(middleware)           — middleware chain (not an entrypoint itself)
//   func handler(c echo.Context) error  — handler signature
//
// Key differences from Gin the engine must handle:
//   1. echo.Context vs gin.Context — different parameter accessor names
//   2. c.QueryParam() vs c.Query()
//   3. c.Param() for path params (same as Gin)
//   4. c.Bind() for body binding (struct tags)
//   5. e.Group() groups — routes registered on group are REACHABLE
//   6. Echo middleware registered with e.Use() does NOT create new entrypoints
// ============================================================================
package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/mattn/go-sqlite3"
)

// ─── Request body structs ─────────────────────────────────────────────────────

type CommandRequest struct {
	Cmd string `json:"cmd"`
}

type SearchRequest struct {
	Query string `json:"query"`
}

type URLRequest struct {
	URL string `json:"url"`
}


// ─── Handlers — all registered with e.GET/POST, all REACHABLE ────────────────

// sqliQueryParam: CWE-89 TP — c.QueryParam() flows to raw SQL
// REACHABLE via e.GET("/sqli", sqliQueryParam)
func sqliQueryParam(c echo.Context) error {
	name := c.QueryParam("name") // user-controlled
	db, _ := sql.Open("sqlite3", "/tmp/testbed.db")
	rows, err := db.Query("SELECT * FROM users WHERE name = '" + name + "'") // CWE-89 TP
	if err != nil {
		return err
	}
	defer rows.Close()
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}

// sqliQueryParamSafe: CWE-89 FP — parameterized, REACHABLE but safe
func sqliQueryParamSafe(c echo.Context) error {
	name := c.QueryParam("name")
	db, _ := sql.Open("sqlite3", "/tmp/testbed.db")
	rows, err := db.Query("SELECT * FROM users WHERE name = ?", name) // FP — parameterized
	if err != nil {
		return err
	}
	defer rows.Close()
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}

// sqliPathParam: CWE-89 TP — c.Param() path param flows to raw SQL
// REACHABLE via e.GET("/user/:id", sqliPathParam)
func sqliPathParam(c echo.Context) error {
	id := c.Param("id") // path param, user-controlled
	db, _ := sql.Open("sqlite3", "/tmp/testbed.db")
	rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)) // CWE-89 TP
	if err != nil {
		return err
	}
	defer rows.Close()
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}

// sqliBodyBind: CWE-89 TP — c.Bind() body field flows to raw SQL
// REACHABLE via e.POST("/search", sqliBodyBind)
func sqliBodyBind(c echo.Context) error {
	var req SearchRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	db, _ := sql.Open("sqlite3", "/tmp/testbed.db")
	rows, err := db.Query("SELECT * FROM products WHERE name LIKE '%" + req.Query + "%'") // CWE-89 TP
	if err != nil {
		return err
	}
	defer rows.Close()
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}

// cmdInjection: CWE-78 TP — c.Bind() body flows to exec.Command
// REACHABLE via e.POST("/cmd", cmdInjection)
func cmdInjection(c echo.Context) error {
	var req CommandRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	out, err := exec.Command("sh", "-c", req.Cmd).Output() // CWE-78 TP
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"output": string(out)})
}

// pathTraversal: CWE-22 TP — c.QueryParam() flows to os.Open
// REACHABLE via e.GET("/file", pathTraversal)
func pathTraversal(c echo.Context) error {
	filename := c.QueryParam("file") // user-controlled
	f, err := os.Open("/srv/files/" + filename) // CWE-22 TP
	if err != nil {
		return err
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	return c.String(http.StatusOK, string(data))
}

// ssrfHandler: CWE-918 TP — c.Bind() URL flows to http.Get
// REACHABLE via e.POST("/fetch", ssrfHandler)
func ssrfHandler(c echo.Context) error {
	var req URLRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	resp, err := http.Get(req.URL) // CWE-918 TP
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return c.JSON(http.StatusOK, map[string]any{"status": resp.StatusCode})
}


// ─── Group handler — routes on group are REACHABLE ───────────────────────────

// sqliInGroup: CWE-89 TP — registered on e.Group("/v2"), REACHABLE
// Engine must follow group.GET() as equivalent to e.GET()
func sqliInGroup(c echo.Context) error {
	term := c.QueryParam("term")
	db, _ := sql.Open("sqlite3", "/tmp/testbed.db")
	rows, err := db.Query("SELECT * FROM items WHERE tag = '" + term + "'") // CWE-89 TP
	if err != nil {
		return err
	}
	defer rows.Close()
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}


// ─── Dead code — NOT_REACHABLE ────────────────────────────────────────────────

// deadSQLi: NOT_REACHABLE — never registered with any route
func deadSQLi(name string) {
	db, _ := sql.Open("sqlite3", "/tmp/testbed.db")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'") // NOT_REACHABLE
}

// deadHandler: NOT_REACHABLE — plain echo handler function, never registered
func deadHandler(c echo.Context) error {
	cmd := c.QueryParam("cmd")
	exec.Command("sh", "-c", cmd).Output() // NOT_REACHABLE
	return nil
}


// ─── Main — engine reads route registrations here ────────────────────────────

func main() {
	e := echo.New()

	// Middleware — does NOT create entrypoints
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Direct routes — REACHABLE
	e.GET("/sqli", sqliQueryParam)
	e.GET("/sqli/safe", sqliQueryParamSafe)
	e.GET("/user/:id", sqliPathParam)
	e.POST("/search", sqliBodyBind)
	e.POST("/cmd", cmdInjection)
	e.GET("/file", pathTraversal)
	e.POST("/fetch", ssrfHandler)

	// Group — routes on group are REACHABLE
	v2 := e.Group("/v2")
	v2.GET("/sqli", sqliInGroup)

	// deadSQLi, deadHandler intentionally NOT registered
	e.Start(":8080")
}
