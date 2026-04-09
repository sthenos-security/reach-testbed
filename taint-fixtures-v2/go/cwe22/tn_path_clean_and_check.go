// Fixture: code_patch · CWE-22 Path Traversal · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: filepath_clean_and_prefix_check
// SOURCE: http_request (r.URL.Query)
// SINK: os.Open (validated path)
// TAINT_HOPS: 1
// NOTES: filepath.Clean + HasPrefix validation
package fileserver

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const baseDir = "/var/data"

func ServeFileSafe(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	fpath := filepath.Join(baseDir, filepath.Clean(filename))
	// SAFE: cleaned path validated against base directory
	if !strings.HasPrefix(fpath, baseDir) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, _ := os.ReadFile(fpath)
	w.Write(data)
}
