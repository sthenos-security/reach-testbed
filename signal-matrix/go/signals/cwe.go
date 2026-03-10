package signals

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

// QueryHandler — CWE-89 REACHABLE: SQL injection via string format
func QueryHandler(c *gin.Context) {
	var req struct{ Name string `json:"name"` }
	c.ShouldBindJSON(&req)

	db, _ := sql.Open("sqlite3", ":memory:")
	// CWE-89 REACHABLE: string formatting in SQL
	query := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", req.Name)
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"rows": rows})
}

// CmdHandler — CWE-78 REACHABLE: OS command injection
func CmdHandler(c *gin.Context) {
	var req struct{ Cmd string `json:"cmd"` }
	c.ShouldBindJSON(&req)
	// CWE-78 REACHABLE: user-controlled command
	out, _ := exec.Command("sh", "-c", req.Cmd).Output()
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}

// SqlInjectionUnknown — CWE-89 UNKNOWN: same package, never called from main
func SqlInjectionUnknown(db *sql.DB, userInput string) {
	query := fmt.Sprintf("DELETE FROM sessions WHERE token='%s'", userInput)
	db.Exec(query) // CWE-89 UNKNOWN
}

// PathTraversalDead — CWE-22 NOT_REACHABLE: never called
func PathTraversalDead(filename string) ([]byte, error) {
	// CWE-22 NOT_REACHABLE: no path sanitization
	return exec.Command("cat", "/var/data/"+filename).Output()
}
