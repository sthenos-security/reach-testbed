// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: prepared_statement_dynamic_table_user_input
// SOURCE: http_request (request.getParameter)
// SINK: PreparedStatement (dynamic table name)
// TAINT_HOPS: 1
// NOTES: PreparedStatement used but table name is user-controlled
import javax.servlet.http.*;
import java.sql.*;

public class TpPreparedDynamicTable extends HttpServlet {
    private Connection conn;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String table = request.getParameter("table");
        int userId = Integer.parseInt(request.getParameter("id"));
        try {
            // VULNERABLE: CWE-89 · table name from user input (params don't help)
            String sql = "SELECT * FROM " + table + " WHERE id = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();
        } catch (SQLException e) {
            response.sendError(500);
        }
    }
}
