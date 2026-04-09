// Fixture: code_patch · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_sprintf_hardcoded_table_parameterized_values
// SOURCE: none (hardcoded constant)
// SINK: db.Query (fmt.Sprintf for table, params for values)
// TAINT_HOPS: 0
// NOTES: Table name from hardcoded map — Fleet FP pattern (softwaredb.go)
package db

import (
	"database/sql"
	"fmt"
)

var osTables = map[string]string{
	"darwin":  "darwin_software",
	"windows": "windows_software",
	"ubuntu":  "ubuntu_software",
}

func LoadSoftware(database *sql.DB, osType string) (*sql.Rows, error) {
	table, ok := osTables[osType]
	if !ok {
		return nil, fmt.Errorf("unsupported OS: %s", osType)
	}
	// SAFE: table name from hardcoded map, WHERE values parameterized
	query := fmt.Sprintf("SELECT * FROM %s WHERE active = ?", table)
	return database.Query(query, true)
}
