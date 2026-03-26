// Dead handlers — NOT_REACHABLE.
//
// These handlers are defined but NEVER registered in main.go.
// The scanner should classify all findings here as NOT_REACHABLE.
package dead

import (
	"fmt"
	"net/http"
	"os/exec"

	"github.com/labstack/echo/v4"
	"golang.org/x/text/language"
)

// SECRET: Dead database password (NOT_REACHABLE — handler never registered)
const DeadDatabasePassword = "postgres://admin:SuperSecret123@db.internal:5432/prod"

// DeadTranslate — CVE-2022-32149 (x/text) — NOT_REACHABLE: never registered.
func DeadTranslate(c echo.Context) error {
	tag, _ := language.Parse(c.FormValue("lang"))
	return c.JSON(http.StatusOK, map[string]string{"lang": tag.String()})
}

// DeadCommand — CWE-78 (command injection) — NOT_REACHABLE: never registered.
func DeadCommand(c echo.Context) error {
	cmd := c.QueryParam("cmd")
	out, _ := exec.Command("sh", "-c", cmd).Output() // CWE NOT_REACHABLE
	return c.String(http.StatusOK, fmt.Sprintf("%s", out))
}
