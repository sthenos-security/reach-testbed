// Dead handlers — NOT_REACHABLE (Type C).
//
// This file is in a separate package that is NEVER imported from
// main.go.  None of these functions are reachable.
//
// CVE-2022-32149 (x/text) — NOT_REACHABLE: file never imported.
// CWE-89 (SQL injection) — NOT_REACHABLE: file never imported.
// SECRET — NOT_REACHABLE: file never imported.
package dead

import (
	"database/sql"
	"fmt"

	"golang.org/x/text/language"
)

// SECRET: Dead admin key (NOT_REACHABLE — package never imported)
const DeadAdminKey = "sk_dead_gin_Np7Wq2xK8m"

// DeadTranslate is NOT_REACHABLE (Type C): in package never imported.
// CVE-2022-32149 (x/text language tag DoS).
func DeadTranslate(input string) string {
	tag, _ := language.Parse(input) // CVE NOT_REACHABLE (Type C)
	return tag.String()
}

// DeadQuery is NOT_REACHABLE (Type C): in package never imported.
// CWE-89 (SQL injection).
func DeadQuery(userInput string) {
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput) // CWE-89 NOT_REACHABLE (Type C)
	db.Query(query)
}
