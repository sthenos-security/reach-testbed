// Fixture: CWE-79 Cross-Site Scripting - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: owasp_encoder_html_escape
// SOURCE: request.getParameter
// SINK: PrintWriter.println (sanitized)
// TAINT_HOPS: 1
// NOTES: OWASP Java Encoder sanitizes before output
import javax.servlet.http.*;
import java.io.*;
import org.owasp.encoder.Encode;

public class TnOWASPEncoder extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        String safe = Encode.forHtml(name);
        response.setContentType("text/html");
        // SAFE: OWASP Encoder escapes HTML entities
        response.getWriter().println("<html><body>Hello " + safe + "</body></html>");
    }
}
