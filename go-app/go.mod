module github.com/reachable/testbed-go

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/text v0.3.7
	gopkg.in/yaml.v2 v2.4.0
)

// CVE Notes:
// golang.org/x/text v0.3.7 - CVE-2022-32149 (DoS via language tag) - REACHABLE
// gopkg.in/yaml.v2 v2.4.0 - CVE-2022-28948 (stack exhaustion) - REACHABLE
