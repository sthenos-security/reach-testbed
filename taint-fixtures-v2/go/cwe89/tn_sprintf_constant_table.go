// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_sprintf_constant_string_table
// SOURCE: none (string constant)
// SINK: db.Query (fmt.Sprintf)
// TAINT_HOPS: 0
// NOTES: fmt.Sprintf with only constant strings — no user input at all
package db

import (
	"database/sql"
	"fmt"
)

const schemaPrefix = "prod"

func CountUsers(database *sql.DB) (int, error) {
	// SAFE: all parts of Sprintf are constants
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s_users WHERE active = 1", schemaPrefix)
	var count int
	err := database.QueryRow(query).Scan(&count)
	return count, err
}
