// Fixture: CWE-22 Path Traversal - Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: model_name_validated_path
// SOURCE: http_request (model name)
// SINK: os.ReadFile (validated)
// TAINT_HOPS: 1
// NOTES: Fixed model loading with path validation
package models

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func LoadModelSafe(modelsDir, modelName string) ([]byte, error) {
	baseDir, _ := filepath.Abs(modelsDir)
	modelPath := filepath.Join(baseDir, modelName)
	resolved, _ := filepath.Abs(modelPath)
	// SAFE: resolved path must start with base directory
	if !strings.HasPrefix(resolved, baseDir) {
		return nil, fmt.Errorf("path traversal: %s", modelName)
	}
	return os.ReadFile(resolved)
}
