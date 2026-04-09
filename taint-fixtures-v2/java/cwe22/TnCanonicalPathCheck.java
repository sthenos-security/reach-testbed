// Fixture: code_patch · CWE-22 Path Traversal · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: canonical_path_validation
// SOURCE: http_request (request.getParameter)
// SINK: new File (validated canonical path)
// TAINT_HOPS: 1
// NOTES: getCanonicalPath resolves traversal, then startsWith validates
import javax.servlet.http.*;
import java.io.*;

public class TnCanonicalPathCheck extends HttpServlet {
    private static final String BASE_DIR = "/var/uploads";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");
        File file = new File(BASE_DIR, filename);
        // SAFE: canonical path resolves ".." and symlinks, then checked
        if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {
            response.sendError(403);
            return;
        }
        response.getOutputStream().write(java.nio.file.Files.readAllBytes(file.toPath()));
    }
}
