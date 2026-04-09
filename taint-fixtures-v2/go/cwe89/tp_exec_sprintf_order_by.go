// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_sprintf_order_by_user_input
// SOURCE: http_request (r.URL.Query)
// SINK: db.Query (fmt.Sprintf ORDER BY)
// TAINT_HOPS: 1
package db

import (
	"database/sql"
	"fmt"
	"net/http"
)

func ListUsers(database *sql.DB, r *http.Request) (*sql.Rows, error) {
	sortCol := r.URL.Query().Get("sort")
	// VULNERABLE: CWE-89 · user-controlled ORDER BY column
	query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortCol)
	return database.Query(query)
}
