// Fixture: code_patch · CWE-22 Path Traversal · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: path_normalize_boundary_check
// SOURCE: function_parameter
// SINK: Paths.get
// TAINT_HOPS: 1
// NOTES: Elasticsearch Environment.java pattern — normalize + startsWith
// REAL_WORLD: elastic/elasticsearch env/Environment.java
import java.nio.file.*;

public class TnPathNormalizeCheck {
    public Path constructRelativeToBase(String basePath, String relSegment) {
        Path baseDir = Paths.get(basePath).toAbsolutePath().normalize();
        Path resolved = baseDir.resolve(relSegment).normalize();
        if (!resolved.startsWith(baseDir)) {
            throw new IllegalArgumentException("Path traversal detected");
        }
        return resolved;
    }
}
