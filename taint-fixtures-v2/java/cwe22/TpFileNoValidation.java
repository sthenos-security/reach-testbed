// Fixture: code_patch · CWE-22 Path Traversal · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: file_constructor_no_validation
// SOURCE: http_request (request.getParameter)
// SINK: new File (unvalidated path)
// TAINT_HOPS: 1
import javax.servlet.http.*;
import java.io.*;

public class TpFileNoValidation extends HttpServlet {
    private static final String BASE_DIR = "/var/uploads";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");
        // VULNERABLE: CWE-22 · no path validation
        File file = new File(BASE_DIR, filename);
        response.getOutputStream().write(java.nio.file.Files.readAllBytes(file.toPath()));
    }
}
