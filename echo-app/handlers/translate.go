// Live handlers — REACHABLE (registered in main.go).
//
// CVE-2022-32149 (golang.org/x/text) — REACHABLE: language.Parse called.
// CVE-2022-28948 (gopkg.in/yaml.v2) — REACHABLE: yaml.Unmarshal called.
// CWE-89 (SQL injection) — REACHABLE: string concat in Search.
// SECRET — REACHABLE: TranslationAPIKey used in Translate response.
package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

// SECRET: Hardcoded API key (REACHABLE — used in Translate handler)
const TranslationAPIKey = "sk_live_echo_translate_key_testbed"

// Translate handles POST /api/translate.
// CVE-2022-32149 (x/text language tag DoS) — REACHABLE.
func Translate(c echo.Context) error {
	lang := c.FormValue("lang")
	tag, err := language.Parse(lang) // CVE REACHABLE
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{
		"language": tag.String(),
		"key":      TranslationAPIKey, // SECRET REACHABLE
	})
}

// LoadConfig handles POST /api/config.
// CVE-2022-28948 (yaml.v2 stack exhaustion) — REACHABLE.
func LoadConfig(c echo.Context) error {
	body, _ := io_read(c)
	var config map[string]interface{}
	err := yaml.Unmarshal(body, &config) // CVE REACHABLE
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, config)
}

// Health handles GET /api/health. Safe endpoint.
func Health(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok", "framework": "echo"})
}

// Search handles GET /api/v2/search?q=...
// CWE-89 (SQL injection) — REACHABLE: string concat with user input.
func Search(c echo.Context) error {
	q := c.QueryParam("q")
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()
	// CWE-89: SQL injection via fmt.Sprintf
	query := fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", q) // CWE REACHABLE
	rows, _ := db.Query(query)
	defer rows.Close()
	return c.JSON(http.StatusOK, map[string]string{"query": query})
}

// helper to read request body
func io_read(c echo.Context) ([]byte, error) {
	buf := make([]byte, 1024*1024)
	n, err := c.Request().Body.Read(buf)
	return buf[:n], err
}
