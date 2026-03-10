package signals

// cve_dead.go — NOT_REACHABLE CVE: functions never called from main or any handler

import (
	"gopkg.in/yaml.v3" // CVE-2022-1996: stack exhaustion via deeply nested YAML
)

// ParseYamlDead — CVE NOT_REACHABLE: yaml.v3 CVE path, never called
func ParseYamlDead(input []byte) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := yaml.Unmarshal(input, &out) // CVE-2022-1996 NOT_REACHABLE
	return out, err
}
