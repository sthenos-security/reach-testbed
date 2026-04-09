// Fixture: code_patch · CWE-22 Path Traversal · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: zip_extraction_hasprefix_validation
// SOURCE: archive (zip entry name)
// SINK: os.Create (validated path)
// TAINT_HOPS: 1
// NOTES: Proper validation — resolved path must start with dest directory
package extractor

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ExtractZipSafe(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	destDir, _ = filepath.Abs(destDir)

	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)
		// SAFE: resolved path validated to stay within dest directory
		if !strings.HasPrefix(filepath.Clean(fpath), destDir) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}
		rc, _ := f.Open()
		outFile, _ := os.Create(fpath)
		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	return nil
}
