// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_parameterized_query
// SOURCE: http_request (r.URL.Query)
// SINK: db.QueryRow (parameterized)
// TAINT_HOPS: 1
// NOTES: Parameterized query — placeholder prevents injection
package db

import (
	"database/sql"
	"net/http"
)

func GetUserSafe(database *sql.DB, r *http.Request) *sql.Row {
	username := r.URL.Query().Get("username")
	// SAFE: parameterized query with placeholder
	return database.QueryRow("SELECT id, username, email FROM users WHERE username = ?", username)
}
