// Fixture: code_patch · CWE-22 Path Traversal · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: paths_get_no_validation
// SOURCE: function_parameter
// SINK: Paths.get
// TAINT_HOPS: 1
// NOTES: No normalize or boundary check after path construction
import java.nio.file.*;

public class TpPathResolveDirect {
    public Path unsafeResolve(String baseDir, String userInput) {
        // VULNERABLE: no validation
        return Paths.get(baseDir, userInput);
    }
}
