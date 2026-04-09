// Fixture: real_world · CWE-89 SQL Injection · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: sql_sprintf_hardcoded_source_list
// SOURCE: none (hardcoded slice)
// SINK: db.Exec (fmt.Sprintf)
// TAINT_HOPS: 0
// NOTES: Fleet FP — softwaredb.go:396 — loadDarwinSoftware uses hardcoded sources
// FLEET_ID: 31264
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package softwaredb

import (
	"database/sql"
	"fmt"
	"strings"
)

var darwinSources = []string{
	"apps",
	"homebrew_packages",
	"firefox_addons",
	"safari_extensions",
	"chrome_extensions",
}

func loadDarwinSoftware(db *sql.DB) error {
	sources := strings.Join(darwinSources, "', '")
	// SAFE: sources are hardcoded, not user-controlled
	// Fleet scanner flagged as CWE-89 because of fmt.Sprintf in SQL
	query := fmt.Sprintf(
		"INSERT INTO software_source (name) VALUES ('%s') ON CONFLICT DO NOTHING",
		sources,
	)
	_, err := db.Exec(query)
	return err
}
