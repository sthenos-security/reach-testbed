// Fixture: code_patch · CWE-22 Path Traversal · Go
// VERDICT: TRUE_POSITIVE
// PATTERN: zip_slip_no_path_validation
// SOURCE: archive (zip entry name)
// SINK: os.Create (unvalidated path)
// TAINT_HOPS: 1
// NOTES: Classic zip-slip — Fleet TP pattern (update.go:754)
package extractor

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func ExtractZipUnsafe(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// VULNERABLE: CWE-22 · no validation of zip entry name
		fpath := filepath.Join(destDir, f.Name)
		rc, _ := f.Open()
		outFile, _ := os.Create(fpath)
		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	return nil
}
