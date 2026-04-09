// Fixture: real_world · SECRET Hardcoded Credential · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: hardcoded_dev_license_key
// SOURCE: none (development constant)
// SINK: none (license check)
// TAINT_HOPS: 0
// NOTES: Fleet FP — serve.go:1891 — hardcoded development license keys
// FLEET_ID: 31795
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package fleet

const (
	// SAFE: development/testing license keys — not production secrets
	devLicenseKey  = "dev-key-not-a-real-license-1234567890"
	testLicenseKey = "test-key-for-integration-tests-0987654321"
)

func isDevMode(licenseKey string) bool {
	return licenseKey == devLicenseKey || licenseKey == testLicenseKey
}
