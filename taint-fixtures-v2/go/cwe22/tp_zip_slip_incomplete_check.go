// Fixture: code_patch · CWE-22 Path Traversal · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: zip_slip_incomplete_dotdot_check
// SOURCE: archive (zip entry name)
// SINK: os.Create (incomplete validation)
// TAINT_HOPS: 1
// NOTES: Checks only for ".." but misses absolute paths — Fleet TP pattern (main.go:265)
package extractor

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ExtractZipWeakCheck(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// VULNERABLE: CWE-22 · only checks for ".." but absolute paths bypass
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
