// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: processbuilder_shell_concat_user_input
// SOURCE: http_request (request.getParameter)
// SINK: ProcessBuilder via sh -c
// TAINT_HOPS: 1
import javax.servlet.http.*;
import java.io.*;

public class TpProcessBuilderShellConcat extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String host = request.getParameter("host");
        // VULNERABLE: CWE-78 · ProcessBuilder with shell wrapper and user input
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 3 " + host);
        Process proc = pb.start();
        response.getWriter().write(new String(proc.getInputStream().readAllBytes()));
    }
}
