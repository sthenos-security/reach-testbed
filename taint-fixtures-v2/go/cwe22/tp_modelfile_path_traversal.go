// Fixture: CWE-22 Path Traversal - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: model_name_path_traversal
// SOURCE: http_request (model name)
// SINK: os.Open
// TAINT_HOPS: 1
// NOTES: Ollama-style CVE-2024-39722 pattern, model name used as file path
// REAL_WORLD: ollama/ollama Modelfile FROM directive (CVE-2024-39722)
package models

import (
	"os"
	"path/filepath"
)

func LoadModel(modelsDir, modelName string) ([]byte, error) {
	// VULNERABLE: modelName could be ../../etc/passwd
	modelPath := filepath.Join(modelsDir, modelName)
	return os.ReadFile(modelPath)
}
