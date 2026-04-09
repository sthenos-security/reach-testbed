// Fixture: CWE-918 SSRF - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: ssrf_user_controlled_url
// SOURCE: http_request (model URL)
// SINK: http.Get
// TAINT_HOPS: 1
// NOTES: Ollama-style user-controlled model URL fetched without validation
// REAL_WORLD: ollama/ollama model pull endpoint
package api

import "net/http"

func PullModel(modelURL string) (*http.Response, error) {
	// VULNERABLE: user-controlled URL - can hit internal services
	return http.Get(modelURL)
}
