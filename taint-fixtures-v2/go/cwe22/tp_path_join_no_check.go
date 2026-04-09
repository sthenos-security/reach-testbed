// Fixture: code_patch · CWE-22 Path Traversal · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: filepath_join_no_validation
// SOURCE: http_request (r.URL.Query)
// SINK: os.Open (unvalidated path)
// TAINT_HOPS: 1
package fileserver

import (
	"net/http"
	"os"
	"path/filepath"
)

func ServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// VULNERABLE: CWE-22 · no validation that path stays within base dir
	fpath := filepath.Join("/var/data", filename)
	data, _ := os.ReadFile(fpath)
	w.Write(data)
}
