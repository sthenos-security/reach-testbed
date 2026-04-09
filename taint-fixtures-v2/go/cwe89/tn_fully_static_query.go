// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_fully_static_query
// SOURCE: none
// SINK: db.Query
// TAINT_HOPS: 0
// NOTES: Entirely static SQL — no variables
package db

import "database/sql"

func CountActiveUsers(database *sql.DB) (int, error) {
	var count int
	// SAFE: fully static SQL query
	err := database.QueryRow("SELECT COUNT(*) FROM users WHERE active = 1").Scan(&count)
	return count, err
}
