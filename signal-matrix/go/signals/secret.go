package signals

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// REACHABLE secrets — ConfigHandler is called from main
const (
	PaymentAPIKey   = "sk_live_goREACH_xxxxxxxxxxxxxxxxxxx" // REACHABLE
	DBPassword      = "db_goREACH_secret_99999"             // REACHABLE
)

// ConfigHandler — SECRET REACHABLE: uses PaymentAPIKey
func ConfigHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"key": PaymentAPIKey[:4] + "****", "db": "connected"})
}

// UNKNOWN secrets — in this file (imported) but functions never called from main
const (
	InternalKeyUnknown = "sk_live_goUNKNOWN_xxxxxxxxxxxxxxxxxxx" // UNKNOWN
	AdminPassUnknown   = "admin_go_unknown_DO_NOT_USE"            // UNKNOWN
)

// GetInternalKeyUnknown — SECRET UNKNOWN: never called from main
func GetInternalKeyUnknown() string { return InternalKeyUnknown }

// NOT_REACHABLE secrets — dead functions, never called
const (
	AWSKeyIDDead     = "AKIAGODEAD0000EXAMPLE"                    // NOT_REACHABLE
	AWSSecretDead    = "goDEAD/K7MDENGbPxRfiCYEXAMPLEKEY0000000" // NOT_REACHABLE
	GitHubTokenDead  = "ghp_goNRxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  // NOT_REACHABLE
)

// GetAwsCredsDead — SECRET NOT_REACHABLE: never called
func GetAwsCredsDead() (string, string) { return AWSKeyIDDead, AWSSecretDead }
