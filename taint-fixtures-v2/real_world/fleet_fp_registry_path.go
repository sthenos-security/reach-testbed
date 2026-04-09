// Fixture: real_world · CWE-798 Hardcoded Credential · Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: windows_registry_path_not_credential
// SOURCE: none (registry path constant)
// SINK: none
// TAINT_HOPS: 0
// NOTES: Fleet FP — windows_registry.go:17 — registry path mistaken for credential
// FLEET_ID: 31821
// AI_VERDICT: FALSE_POSITIVE · conf=HIGH
package registry

const (
	// SAFE: Windows registry path — NOT a hardcoded credential
	fleetRegistryPath = `HKLM\SOFTWARE\FleetDM\Orbit`
	orbitNodeKeyPath  = `HKLM\SOFTWARE\FleetDM\Orbit\Info`
)

func GetRegistryPath() string {
	return fleetRegistryPath
}
