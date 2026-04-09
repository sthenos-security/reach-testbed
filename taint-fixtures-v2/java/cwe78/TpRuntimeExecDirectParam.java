// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: runtime_exec_direct_user_command
// SOURCE: http_request (request.getParameter)
// SINK: Runtime.exec
// TAINT_HOPS: 1
import javax.servlet.http.*;
import java.io.*;

public class TpRuntimeExecDirectParam extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String cmd = request.getParameter("cmd");
        // VULNERABLE: CWE-78 · user-controlled command string
        Process proc = Runtime.getRuntime().exec(cmd);
        response.getWriter().write(new String(proc.getInputStream().readAllBytes()));
    }
}
