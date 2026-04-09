// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_query_sprintf_user_input
// SOURCE: http_request (r.FormValue)
// SINK: db.Query (fmt.Sprintf)
// TAINT_HOPS: 1
package db

import (
	"database/sql"
	"fmt"
	"net/http"
)

func SearchUsers(database *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.FormValue("name")
	// VULNERABLE: CWE-89 · fmt.Sprintf with user input in WHERE clause
	query := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", name)
	return database.Query(query)
}
