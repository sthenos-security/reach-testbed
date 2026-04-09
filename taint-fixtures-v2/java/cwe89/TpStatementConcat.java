// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: statement_string_concat_user_input
// SOURCE: http_request (request.getParameter)
// SINK: Statement.executeQuery (string concat)
// TAINT_HOPS: 1
import javax.servlet.http.*;
import java.sql.*;

public class TpStatementConcat extends HttpServlet {
    private Connection conn;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String username = request.getParameter("username");
        try {
            Statement stmt = conn.createStatement();
            // VULNERABLE: CWE-89 · Statement with string concatenation
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
        } catch (SQLException e) {
            response.sendError(500);
        }
    }
}
