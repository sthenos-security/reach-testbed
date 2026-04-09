// Fixture: CWE-79 Cross-Site Scripting - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: servlet_writer_html_concat
// SOURCE: request.getParameter
// SINK: PrintWriter.println
// TAINT_HOPS: 1
// NOTES: Classic servlet XSS - user input written directly to response
// REAL_WORLD: Common in legacy Java servlets
import javax.servlet.http.*;
import java.io.*;

public class TpServletWriterConcat extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        // VULNERABLE: user input in HTML output
        out.println("<html><body>Hello " + name + "</body></html>");
    }
}
