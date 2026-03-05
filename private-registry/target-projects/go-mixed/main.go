// Package main — Go mixed registry demo app.
//
// Uses public modules via Athens proxy (golang.org/x/net, gin).
// GOPROXY must point to Athens: http://localhost:3000,direct
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/html"
	"strings"
)

func main() {
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.GET("/parse", func(c *gin.Context) {
		// Exercises golang.org/x/net/html (CVE target)
		doc, err := html.Parse(strings.NewReader("<html><body>test</body></html>"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"parsed": doc.Type})
	})

	r.Run(":8080")
}
