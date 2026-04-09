// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_allowlist_order_by
// SOURCE: http_request (r.URL.Query)
// SINK: db.Query (fmt.Sprintf ORDER BY)
// TAINT_HOPS: 1
// NOTES: User input validated against allowlist before use in ORDER BY
package db

import (
	"database/sql"
	"fmt"
	"net/http"
)

var allowedSortColumns = map[string]bool{
	"name": true, "email": true, "created_at": true,
}

func ListUsersSafe(database *sql.DB, r *http.Request) (*sql.Rows, error) {
	sortCol := r.URL.Query().Get("sort")
	if !allowedSortColumns[sortCol] {
		sortCol = "name" // default
	}
	// SAFE: sort column validated against allowlist
	query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortCol)
	return database.Query(query)
}
