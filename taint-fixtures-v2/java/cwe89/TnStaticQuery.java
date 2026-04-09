// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: static_query_no_user_input
// SOURCE: none
// SINK: Statement.executeQuery
// TAINT_HOPS: 0
// NOTES: Fully static SQL query
import java.sql.*;

public class TnStaticQuery {
    private Connection conn;

    public int countActiveUsers() throws SQLException {
        Statement stmt = conn.createStatement();
        // SAFE: fully static SQL query
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM users WHERE active = 1");
        rs.next();
        return rs.getInt(1);
    }
}
