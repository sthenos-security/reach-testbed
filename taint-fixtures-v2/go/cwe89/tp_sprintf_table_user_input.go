// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_sprintf_table_name_from_http
// SOURCE: http_request (r.URL.Query)
// SINK: db.Query (fmt.Sprintf table name)
// TAINT_HOPS: 1
package db

import (
	"database/sql"
	"fmt"
	"net/http"
)

func QueryTable(database *sql.DB, r *http.Request) (*sql.Rows, error) {
	table := r.URL.Query().Get("table")
	id := r.URL.Query().Get("id")
	// VULNERABLE: CWE-89 · user-controlled table name
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = '%s'", table, id)
	return database.Query(query)
}
