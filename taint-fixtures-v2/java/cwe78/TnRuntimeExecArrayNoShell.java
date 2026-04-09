// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: runtime_exec_array_no_shell
// SOURCE: http_request (request.getParameter)
// SINK: Runtime.exec (String[])
// TAINT_HOPS: 1
// NOTES: Array form without shell wrapper — arguments not interpreted
import javax.servlet.http.*;
import java.io.*;

public class TnRuntimeExecArrayNoShell extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");
        // SAFE: array form, no shell wrapper — user input is just an argument
        String[] cmd = {"ls", "-la", filename};
        Process proc = Runtime.getRuntime().exec(cmd);
        response.getWriter().write(new String(proc.getInputStream().readAllBytes()));
    }
}
