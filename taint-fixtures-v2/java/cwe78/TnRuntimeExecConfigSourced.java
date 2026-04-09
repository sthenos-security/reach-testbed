// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: runtime_exec_config_sourced
// SOURCE: config (System.getProperty)
// SINK: Runtime.exec
// TAINT_HOPS: 1
// NOTES: System property is server-controlled, not user-controlled
import java.io.*;

public class TnRuntimeExecConfigSourced {
    public String runTool() throws IOException {
        String toolPath = System.getProperty("app.scanner.path", "/usr/bin/scanner");
        // SAFE: command path from system property — server-controlled
        Process proc = Runtime.getRuntime().exec(new String[]{toolPath, "--scan"});
        return new String(proc.getInputStream().readAllBytes());
    }
}
