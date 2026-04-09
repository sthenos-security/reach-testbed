// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: processbuilder_shell_concat_pipe
// SOURCE: function_parameter
// SINK: ProcessBuilder
// TAINT_HOPS: 1
// NOTES: String concat with pipe through /bin/sh -c
import java.io.*;

public class TpShellConcatPipe {
    public void shellExec(String filename) throws IOException {
        // VULNERABLE: concat + pipe + shell
        String cmd = "grep ERROR " + filename + " | wc -l";
        new ProcessBuilder("/bin/sh", "-c", cmd).start();
    }
}
