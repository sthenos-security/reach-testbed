// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: runtime_exec_array_shell_wrapper
// SOURCE: http_request (request.getParameter)
// SINK: Runtime.exec (String[]) via sh -c
// TAINT_HOPS: 1
import javax.servlet.http.*;
import java.io.*;

public class TpRuntimeExecArrayShell extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String userInput = request.getParameter("input");
        // VULNERABLE: CWE-78 · array form but shell wrapper concatenates user input
        String[] cmd = {"sh", "-c", "echo " + userInput};
        Process proc = Runtime.getRuntime().exec(cmd);
        response.getWriter().write(new String(proc.getInputStream().readAllBytes()));
    }
}
