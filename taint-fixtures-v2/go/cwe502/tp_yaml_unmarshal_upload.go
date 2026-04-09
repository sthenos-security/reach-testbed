// Fixture: CWE-502 Deserialization - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: yaml_unmarshal_user_upload
// SOURCE: http_request body
// SINK: yaml.Unmarshal
// TAINT_HOPS: 1
// NOTES: YAML unmarshal of user-uploaded content - can trigger custom UnmarshalYAML
package api

import (
	"io"
	"net/http"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name    string   `yaml:"name"`
	Plugins []string `yaml:"plugins"`
}

func UploadConfig(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var config Config
	// VULNERABLE: untrusted YAML from user upload
	yaml.Unmarshal(body, &config)
}
