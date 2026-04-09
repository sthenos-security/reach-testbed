// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: runtime_exec_shell_concat_user_input
// SOURCE: http_request (request.getParameter)
// SINK: Runtime.exec via sh -c
// TAINT_HOPS: 1
import javax.servlet.http.*;
import java.io.*;

public class TpRuntimeExecUserInput extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");
        // VULNERABLE: CWE-78 · shell wrapper with user input concatenation
        Process proc = Runtime.getRuntime().exec("sh -c ls " + filename);
        response.getWriter().write(new String(proc.getInputStream().readAllBytes()));
    }
}
