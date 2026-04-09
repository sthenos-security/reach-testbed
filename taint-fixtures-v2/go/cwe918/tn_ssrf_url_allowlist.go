// Fixture: CWE-918 SSRF - Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: ssrf_url_allowlist_validation
// SOURCE: http_request (model URL)
// SINK: http.Get (validated)
// TAINT_HOPS: 1
// NOTES: URL validated against allowlist of trusted registries
package api

import (
	"fmt"
	"net/http"
	"net/url"
)

var trustedHosts = map[string]bool{
	"registry.ollama.ai": true,
	"huggingface.co":     true,
}

func PullModelSafe(modelURL string) (*http.Response, error) {
	u, err := url.Parse(modelURL)
	if err != nil {
		return nil, err
	}
	if !trustedHosts[u.Hostname()] {
		return nil, fmt.Errorf("untrusted host: %s", u.Hostname())
	}
	// SAFE: only trusted hosts allowed
	return http.Get(modelURL)
}
