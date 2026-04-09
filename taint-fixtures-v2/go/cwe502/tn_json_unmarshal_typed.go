// Fixture: CWE-502 Deserialization - Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: json_unmarshal_typed_struct
// SOURCE: http_request body
// SINK: json.Unmarshal
// TAINT_HOPS: 1
// NOTES: encoding/json into typed struct - no code execution possible
package api

import (
	"encoding/json"
	"io"
	"net/http"
)

type UserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func HandleUser(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req UserRequest
	// SAFE: JSON into typed struct - no code execution, only data
	json.Unmarshal(body, &req)
}
