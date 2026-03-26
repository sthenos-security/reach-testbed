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
	"io"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

// SECRET: Hardcoded API key (REACHABLE — used in Translate handler)
const TranslationAPIKey = "sk_live_gin_translate_key_testbed"

// Translate handles POST /api/translate.
// CVE-2022-32149 (x/text language tag DoS) — REACHABLE.
func Translate(c *gin.Context) {
	lang := c.PostForm("lang")
	tag, err := language.Parse(lang) // CVE REACHABLE
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"language": tag.String(),
		"key":      TranslationAPIKey, // SECRET REACHABLE
	})
}

// LoadConfig handles POST /api/config.
// CVE-2022-28948 (yaml.v2 stack exhaustion) — REACHABLE.
func LoadConfig(c *gin.Context) {
	body, _ := io.ReadAll(c.Request.Body)
	var config map[string]interface{}
	if err := yaml.Unmarshal(body, &config); err != nil { // CVE REACHABLE
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, config)
}

// Health handles GET /api/health. Safe endpoint.
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "framework": "gin"})
}

// Search handles GET /api/v2/search?q=...
// CWE-89 (SQL injection) — REACHABLE: string concat with user input.
func Search(c *gin.Context) {
	q := c.Query("q")
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()
	query := fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", q) // CWE REACHABLE
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"query": query})
}

// ═══════════════════════════════════════════════════════════════════
// TYPE B DEAD CODE — function in same package as live handlers, but
// never registered via r.GET/r.POST in main.go and never called
// from any registered handler.
// ═══════════════════════════════════════════════════════════════════

// DeadInlineSearch is NOT_REACHABLE (Type B): in live package but
// never registered or called from any route handler.
// CWE-78 (command injection) — NOT_REACHABLE.
func DeadInlineSearch(c *gin.Context) {
	cmd := c.Query("cmd")
	out, _ := exec.Command("sh", "-c", cmd).Output() // CWE-78 NOT_REACHABLE (Type B)
	c.String(http.StatusOK, string(out))
}
