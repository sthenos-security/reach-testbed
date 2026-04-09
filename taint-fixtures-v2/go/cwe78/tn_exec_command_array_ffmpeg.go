// Fixture: CWE-78 Command Injection - Go
// VERDICT: TRUE_NEGATIVE
// PATTERN: exec_command_array_form
// SOURCE: function_parameter (filename)
// SINK: exec.Command (array form)
// TAINT_HOPS: 1
// NOTES: Fixed version of CVE-2024-2029 - array args prevent shell injection
// REAL_WORLD: go-skynet/LocalAI audioToWav (fixed)
package audio

import "os/exec"

func AudioToWavSafe(inputFile, outputFile string) error {
	// SAFE: array form prevents shell interpretation
	return exec.Command("ffmpeg", "-i", inputFile, "-acodec", "pcm_s16le",
		"-ar", "16000", "-ac", "1", outputFile).Run()
}
