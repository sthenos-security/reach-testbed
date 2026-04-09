// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: processbuilder_array_no_shell
// SOURCE: http_request (request.getParameter)
// SINK: ProcessBuilder (no shell wrapper)
// TAINT_HOPS: 1
// NOTES: ProcessBuilder with separate arguments — no shell interpretation
import javax.servlet.http.*;
import java.io.*;

public class TnProcessBuilderNoShell extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String host = request.getParameter("host");
        // SAFE: separate arguments, no shell wrapper — no metacharacter interpretation
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", host);
        Process proc = pb.start();
        response.getWriter().write(new String(proc.getInputStream().readAllBytes()));
    }
}
