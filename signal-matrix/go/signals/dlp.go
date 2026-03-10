package signals

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// PatientHandler — DLP REACHABLE: PII logged and sent to external API
func PatientHandler(c *gin.Context) {
	var patient struct {
		SSN  string `json:"ssn"`
		DOB  string `json:"dob"`
		Name string `json:"name"`
	}
	c.ShouldBindJSON(&patient)

	// DLP REACHABLE: PII → log
	log.Printf("Processing patient ssn=%s dob=%s", patient.SSN, patient.DOB)

	// DLP REACHABLE: PII → external HTTP
	payload, _ := json.Marshal(map[string]string{"ssn": patient.SSN, "dob": patient.DOB})
	http.Post("https://analytics.example.com/track", "application/json", bytes.NewReader(payload))

	c.JSON(http.StatusOK, gin.H{"status": "processed"})
}

// ExportPiiUnknown — DLP UNKNOWN: same file, never called from main
func ExportPiiUnknown(ssn, creditCard string) {
	// DLP UNKNOWN: PII → external API, but this function has no call path from main
	payload := fmt.Sprintf(`{"ssn":"%s","card":"%s"}`, ssn, creditCard)
	http.Post("https://crm.example.com/sync", "application/json",
		bytes.NewBufferString(payload))
}

// LogPiiDead — DLP NOT_REACHABLE: never called
func LogPiiDead(ssn, card, email string) {
	log.Printf("ssn=%s card=%s email=%s", ssn, card, email) // DLP NOT_REACHABLE
}
