// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: runtime_exec_fully_literal
// SOURCE: none (literal string)
// SINK: Runtime.exec
// TAINT_HOPS: 0
// NOTES: Fully literal command — no user input
import java.io.*;

public class TnRuntimeExecLiteral {
    public String listFiles() throws IOException {
        // SAFE: fully literal command string
        Process proc = Runtime.getRuntime().exec("ls -la /tmp");
        return new String(proc.getInputStream().readAllBytes());
    }
}
