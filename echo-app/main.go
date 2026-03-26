// Echo application — entrypoint.
//
// Handlers registered via e.GET/e.POST are REACHABLE.
// Handlers in dead/ that are never registered are NOT_REACHABLE.
package main

import (
	"github.com/labstack/echo/v4"
	"github.com/sthenos-security/reach-testbed/echo-app/handlers"
)

// NOTE: dead/unused.go defines handlers but they are NEVER registered below.

func main() {
	e := echo.New()

	// Live routes (REACHABLE)
	e.POST("/api/translate", handlers.Translate)
	e.POST("/api/config", handlers.LoadConfig)
	e.GET("/api/health", handlers.Health)

	// Route group (REACHABLE)
	api := e.Group("/api/v2")
	api.GET("/search", handlers.Search)

	// NOTE: handlers.DeadTranslate is never registered — NOT_REACHABLE

	e.Logger.Fatal(e.Start(":8080"))
}
