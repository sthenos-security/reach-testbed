// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: runtime_exec_string_concat
// SOURCE: function_parameter
// SINK: Runtime.exec
// TAINT_HOPS: 1
// NOTES: User input concatenated into shell command
import java.io.*;

public class TpRuntimeExecConcat {
    public void runtimeExecWithInput(String userPath) throws IOException {
        // VULNERABLE: user input in command string
        Runtime.getRuntime().exec("cat " + userPath);
    }
}
