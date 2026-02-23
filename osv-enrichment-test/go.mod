module github.com/reachable/testbed-osv-enrichment

go 1.21

require (
	golang.org/x/crypto v0.26.0
	golang.org/x/net v0.23.0
)

// OSV Enrichment Test Cases
// These versions have well-known CVEs with confirmed GO-VULN-IDs in OSV:
//
// golang.org/x/crypto v0.26.0
//   CVE-2024-45337 / GHSA-v778-237x-gjrc → GO-2024-3321
//   "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass"
//
// golang.org/x/net v0.23.0
//   CVE-2023-44487 / GHSA-qppj-fm56-g4cc → GO-2023-2102  (HTTP/2 Rapid Reset)
//   CVE-2024-45338 / GHSA-w32m-9786-jp63 → GO-2024-3333  (non-linear HTML parsing)
//
// Expected enrichment after scan:
//   go_vuln_id   → populated (GO-XXXX-XXXX)
//   epss_score   → populated (float 0.0-1.0)
//   is_kev       → populated (true/false)
