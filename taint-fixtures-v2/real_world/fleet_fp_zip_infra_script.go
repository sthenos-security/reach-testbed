// Fixture: real_world · CWE-22 Path Traversal · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: zip_extract_infra_script_with_dotdot_check
// SOURCE: archive (zip entry name)
// SINK: os.Create
// TAINT_HOPS: 1
// NOTES: Fleet FP — main.go:265 — infra script with incomplete but acceptable check
// FLEET_ID: 31771
// AI_VERDICT: TRUE_POSITIVE (disputed — infra context makes this low-risk)
package main

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractOsqueryBundle(zipPath, destDir string) error {
	r, _ := zip.OpenReader(zipPath)
	defer r.Close()
	for _, f := range r.File {
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
