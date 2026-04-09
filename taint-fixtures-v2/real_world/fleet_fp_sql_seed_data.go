// Fixture: real_world · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_seed_data_infra_script
// SOURCE: none (seed data file)
// SINK: db.Exec (string variable)
// TAINT_HOPS: 0
// NOTES: Fleet FP — seed_queries.go:59 — seed data script with no user input
// FLEET_ID: 31487
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package main

import (
	"database/sql"
	"fmt"
)

var seedQueries = []string{
	"SELECT hostname, os_version FROM system_info;",
	"SELECT name, version FROM apps;",
	"SELECT name, path FROM programs;",
}

func seedDatabase(db *sql.DB) error {
	for _, query := range seedQueries {
		// SAFE: queries are from hardcoded seed data, no user input
		_, err := db.Exec(fmt.Sprintf("INSERT INTO queries (query) VALUES ('%s')", query))
		if err != nil {
			return err
		}
	}
	return nil
}
