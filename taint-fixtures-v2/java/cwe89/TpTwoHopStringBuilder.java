// Fixture: CWE-89 SQL Injection - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: multi_hop_stringbuilder_sql
// SOURCE: request.getParameter
// SINK: Statement.executeQuery
// TAINT_HOPS: 2
// NOTES: Taint flows through StringBuilder to SQL query
import java.sql.*;
import javax.servlet.http.*;

public class TpTwoHopStringBuilder {
    public void search(HttpServletRequest request, Connection conn) throws Exception {
        String term = request.getParameter("search");
        StringBuilder sb = new StringBuilder("SELECT * FROM products WHERE name LIKE '%");
        sb.append(term);
        sb.append("%'");
        String query = sb.toString();
        // VULNERABLE: 2-hop through StringBuilder
        conn.createStatement().executeQuery(query);
    }
}
