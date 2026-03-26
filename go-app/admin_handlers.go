// Admin handlers — NOT_REACHABLE (Type A).
//
// This file is in the main package (same as main.go), so it IS
// compiled and its symbols are accessible.  But these handler
// functions are never passed to r.GET/r.POST/r.Group in main.go,
// so no HTTP request can reach them.
//
// CWE-78 (command injection) — NOT_REACHABLE: handler never registered.
// SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
package main

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// SECRET: Hardcoded admin token (NOT_REACHABLE — handler never registered)
const AdminToken = "adm_live_gin_7mXq2K"

// AdminExec is NOT_REACHABLE (Type A): defined in main package but
// never registered on the Gin router in main().
// CWE-78 (command injection) — NOT_REACHABLE.
func AdminExec(c *gin.Context) {
	cmd := c.PostForm("cmd")
	out, _ := exec.Command("sh", "-c", cmd).Output() // CWE-78 NOT_REACHABLE (Type A)
	c.String(http.StatusOK, string(out))
}

// AdminTokenEndpoint is NOT_REACHABLE (Type A): handler never registered.
// SECRET — NOT_REACHABLE.
func AdminTokenEndpoint(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"token": AdminToken, // SECRET NOT_REACHABLE (Type A)
	})
}
