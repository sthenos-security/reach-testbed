// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_query_string_concat
// SOURCE: http_request (r.URL.Query)
// SINK: db.Query (string concat)
// TAINT_HOPS: 1
package db

import (
	"database/sql"
	"net/http"
)

func GetUser(database *sql.DB, r *http.Request) (*sql.Row, error) {
	username := r.URL.Query().Get("username")
	// VULNERABLE: CWE-89 · string concatenation in SQL query
	query := "SELECT id, username, email FROM users WHERE username = '" + username + "'"
	return database.QueryRow(query), nil
}
