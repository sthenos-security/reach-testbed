// Fixture: CWE-89 SQL Injection - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: vector_store_parameterized_filter
// SOURCE: function_parameter (filter expression)
// SINK: PreparedStatement
// TAINT_HOPS: 1
// NOTES: Fixed version - parameterized query for vector store filters
import java.sql.*;

public class TnVectorStoreParameterized {
    public ResultSet queryWithFilter(Connection conn, String key, String value) throws SQLException {
        // SAFE: parameterized query
        String sql = "SELECT * FROM embeddings WHERE metadata ->> ? = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, key);
        ps.setString(2, value);
        return ps.executeQuery();
    }
}
