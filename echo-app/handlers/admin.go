// Admin handlers — NOT_REACHABLE (Type A).
//
// This file is in the handlers package which IS imported in main.go,
// so these functions are compiled and accessible, but they are never
// registered via e.GET/e.POST/e.Group in main.go.
//
// CWE-78 (command injection) — NOT_REACHABLE: handler never registered.
// SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
package handlers

import (
	"net/http"
	"os/exec"

	"github.com/labstack/echo/v4"
)

// SECRET: Hardcoded admin token (NOT_REACHABLE — handler never registered)
const AdminToken = "adm_live_echo_7mXq2K"

// AdminExec is NOT_REACHABLE (Type A): in imported package but never
// registered in main.go.
// CWE-78 (command injection) — NOT_REACHABLE.
func AdminExec(c echo.Context) error {
	cmd := c.FormValue("cmd")
	out, _ := exec.Command("sh", "-c", cmd).Output() // CWE-78 NOT_REACHABLE (Type A)
	return c.String(http.StatusOK, string(out))
}

// AdminTokenEndpoint is NOT_REACHABLE (Type A): handler never registered.
// SECRET — NOT_REACHABLE.
func AdminTokenEndpoint(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"token": AdminToken, // SECRET NOT_REACHABLE (Type A)
	})
}
