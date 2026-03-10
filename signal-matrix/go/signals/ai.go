package signals

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LlmHandler — AI REACHABLE: user input sent directly to LLM
func LlmHandler(c *gin.Context) {
	var req struct{ Prompt string `json:"prompt"` }
	c.ShouldBindJSON(&req)

	// LLM01 REACHABLE: unsanitized user prompt to OpenAI
	payload, _ := json.Marshal(map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": req.Prompt}, // VIOLATION: unsanitized
		},
	})
	http.Post("https://api.openai.com/v1/chat/completions",
		"application/json", bytes.NewReader(payload))
	c.JSON(200, gin.H{"status": "sent"})
}

// RunUncheckedLlmUnknown — AI UNKNOWN: same file, never called from main
func RunUncheckedLlmUnknown(userInput string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]string{{"role": "user", "content": userInput}},
	})
	// LLM01 UNKNOWN: never on call path from main
	http.Post("https://api.openai.com/v1/chat/completions",
		"application/json", bytes.NewReader(payload))
}

// CallLlmWithPiiDead — AI + DLP NOT_REACHABLE: never called
func CallLlmWithPiiDead(ssn, diagnosis string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"messages": []map[string]string{{
			"role": "user",
			"content": "ssn=" + ssn + " diagnosis=" + diagnosis, // DLP+AI NOT_REACHABLE
		}},
	})
	http.Post("https://api.openai.com/v1/chat/completions",
		"application/json", bytes.NewReader(payload))
}
