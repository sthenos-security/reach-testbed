// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: string_format_sql
// SOURCE: function_parameter
// SINK: String.format
// TAINT_HOPS: 1
// NOTES: String.format with %s in SQL query — classic SQLi
public class TpSqlStringFormat {
    public String buildQuery(String username, String password) {
        // VULNERABLE: String.format with user input
        return String.format(
            "SELECT * FROM users WHERE username='%s' AND password='%s'",
            username, password
        );
    }
}
