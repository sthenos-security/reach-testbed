// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: sandboxed_execution_blocked
// SOURCE: none (literal)
// SINK: Runtime.exec
// TAINT_HOPS: 0
// NOTES: Elasticsearch-style — SecurityManager blocks process spawning
// REAL_WORLD: elastic/elasticsearch issue #64755
import java.io.*;

public class TnProcessBuilderSandboxed {
    public void attemptExecInSandbox() {
        try {
            // SAFE: SecurityManager policy blocks Runtime.exec
            Process p = Runtime.getRuntime().exec("id -u");
        } catch (IOException e) {
            // Expected: Permission denied
        }
    }
}
