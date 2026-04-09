// Fixture: CWE-78 Command Injection - Go
// VERDICT: TRUE_POSITIVE
// PATTERN: exec_command_shell_sprintf
// SOURCE: function_parameter (filename)
// SINK: exec.Command with bash -c
// TAINT_HOPS: 1
// NOTES: LocalAI-style CVE-2024-2029 pattern, filename in ffmpeg shell command
// REAL_WORLD: go-skynet/LocalAI audioToWav (CVE-2024-2029)
package audio

import (
	"fmt"
	"os/exec"
)

func AudioToWav(inputFile, outputFile string) error {
	// VULNERABLE: filename concatenated into shell command
	cmd := fmt.Sprintf("ffmpeg -i %s -acodec pcm_s16le -ar 16000 -ac 1 %s", inputFile, outputFile)
	return exec.Command("bash", "-c", cmd).Run()
}
