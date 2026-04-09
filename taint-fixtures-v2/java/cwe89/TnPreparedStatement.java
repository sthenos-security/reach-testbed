// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: prepared_statement_parameterized
// SOURCE: http_request (request.getParameter)
// SINK: PreparedStatement (parameterized)
// TAINT_HOPS: 1
// NOTES: Properly parameterized PreparedStatement
import javax.servlet.http.*;
import java.sql.*;

public class TnPreparedStatement extends HttpServlet {
    private Connection conn;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String username = request.getParameter("username");
        try {
            // SAFE: properly parameterized PreparedStatement
            PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM users WHERE username = ?"
            );
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
        } catch (SQLException e) {
            response.sendError(500);
        }
    }
}
