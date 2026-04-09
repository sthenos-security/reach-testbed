// Fixture: real_world · CWE-22 Path Traversal · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: zip_slip_update_mechanism
// SOURCE: archive (zip entry from network)
// SINK: os.Create (production update path)
// TAINT_HOPS: 1
// NOTES: Fleet TP — update.go:754 — production update mechanism processes untrusted archives
// FLEET_ID: 31762
// AI_VERDICT: TRUE_POSITIVE · sev=CRITICAL · conf=HIGH
package update

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractUpdate(zipPath, destDir string) error {
	r, _ := zip.OpenReader(zipPath)
	defer r.Close()
	for _, f := range r.File {
		// VULNERABLE: CWE-22 · only checks for ".." but absolute paths bypass this
		// In production update context, archives come from network
		if strings.Contains(f.Name, "..") {
			continue
		}
		fpath := filepath.Join(destDir, f.Name)
		rc, _ := f.Open()
		outFile, _ := os.Create(fpath)
		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	return nil
}
