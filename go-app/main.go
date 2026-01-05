package main

/*
Go Test App - Known Vulnerabilities

REACHABLE CVEs:
- CVE-2022-32149 (golang.org/x/text) - triggered via /api/translate
- CVE-2022-28948 (gopkg.in/yaml.v2) - triggered via /api/config

REACHABLE SECRETS:
- Hardcoded API key in translate handler
*/

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

// ============================================================================
// REACHABLE SECRET
// ============================================================================
const (
	TranslationAPIKey = "tr-api-key-xxxxxxxxxxxxxxxxx"
	DatabasePassword  = "db_secret_password_456"
)

func main() {
	r := gin.Default()

	// REACHABLE CVE endpoint
	r.POST("/api/translate", translateHandler)

	// REACHABLE CVE endpoint
	r.POST("/api/config", configHandler)

	// SAFE endpoint
	r.GET("/api/health", healthHandler)

	r.Run(":8080")
}

// ============================================================================
// REACHABLE CVE: golang.org/x/text (CVE-2022-32149)
// Language tag parsing DoS
// ============================================================================
func translateHandler(c *gin.Context) {
	var req struct {
		Text     string `json:"text"`
		FromLang string `json:"from"`
		ToLang   string `json:"to"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// CVE-2022-32149: DoS via malformed language tag
	// Attacker sends extremely long/malformed language tag
	fromTag, err := language.Parse(req.FromLang)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from language"})
		return
	}

	toTag, err := language.Parse(req.ToLang)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to language"})
		return
	}

	// Using hardcoded API key - REACHABLE SECRET
	_ = TranslationAPIKey

	c.JSON(http.StatusOK, gin.H{
		"translated": req.Text,
		"from":       fromTag.String(),
		"to":         toTag.String(),
	})
}

// ============================================================================
// REACHABLE CVE: gopkg.in/yaml.v2 (CVE-2022-28948)
// Stack exhaustion via deeply nested YAML
// ============================================================================
func configHandler(c *gin.Context) {
	var yamlContent []byte
	if err := c.ShouldBindJSON(&struct {
		Content string `json:"content"`
	}{}); err != nil {
		yamlContent = []byte(c.PostForm("content"))
	}

	// CVE-2022-28948: Stack exhaustion via recursive aliases
	var config map[string]interface{}
	if err := yaml.Unmarshal(yamlContent, &config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"config": config})
}

// ============================================================================
// SAFE ENDPOINT
// ============================================================================
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ============================================================================
// UNREACHABLE CODE - Never called
// ============================================================================
func unusedDatabaseConnection() {
	// This function is never called from any HTTP handler
	// Uses hardcoded password but UNREACHABLE
	_ = DatabasePassword
}
