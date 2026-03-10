package signals

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/language" // CVE-2022-32149: DoS via malformed language tag
)

// TranslateHandler — CVE REACHABLE: calls language.Parse with user input
func TranslateHandler(c *gin.Context) {
	var req struct{ Lang string `json:"lang"` }
	c.ShouldBindJSON(&req)
	// CVE-2022-32149 REACHABLE
	tag, err := language.Parse(req.Lang)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tag": tag.String()})
}

// SafeVersion — called from HealthHandler (UNKNOWN path)
func SafeVersion() string { return "1.0.0" }

// ParseLangUnknown — CVE UNKNOWN: language.Parse called but this func never invoked from main
func ParseLangUnknown(raw string) string {
	tag, _ := language.Parse(raw) // CVE-2022-32149 UNKNOWN
	return tag.String()
}

// HealthHandler calls only SafeVersion (safe) — language package on import graph but no CVE path
func HealthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": SafeVersion()})
}
