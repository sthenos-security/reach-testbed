// Gin application — entrypoint.
//
// Handlers registered via r.GET/r.POST are REACHABLE.
// Handlers in the handlers package that are defined but never
// registered are NOT_REACHABLE (Type B).
// Handlers in dead/ package (never imported) are NOT_REACHABLE (Type C).
// The handlers.AdminExec handler IS in the imported handlers package
// but is never registered on any route (Type A).
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/sthenos-security/reach-testbed/gin-app/handlers"
)

// NOTE: dead/unused.go is in a separate package NEVER imported (Type C).
// NOTE: handlers.AdminExec IS in the imported package but never r.POST()'d (Type A).
// NOTE: handlers.DeadInlineSearch IS in the imported package, never called (Type B).

func main() {
	r := gin.Default()

	// Live routes (REACHABLE)
	r.POST("/api/translate", handlers.Translate)
	r.POST("/api/config", handlers.LoadConfig)
	r.GET("/api/health", handlers.Health)

	// Route group (REACHABLE)
	api := r.Group("/api/v2")
	api.GET("/search", handlers.Search)

	// NOTE: handlers.AdminExec is never registered — NOT_REACHABLE (Type A)
	// NOTE: handlers.DeadInlineSearch is never called — NOT_REACHABLE (Type B)

	r.Run(":8080")
}
