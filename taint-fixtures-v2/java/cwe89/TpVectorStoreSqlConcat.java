// Fixture: CWE-89 SQL Injection - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: vector_store_filter_sql_concat
// SOURCE: function_parameter (filter expression)
// SINK: String.format SQL
// TAINT_HOPS: 1
// NOTES: Spring AI-style CVE-2026-22730 pattern, filter expression in SQL
// REAL_WORLD: spring-projects/spring-ai MariaDBFilterExpressionConverter
public class TpVectorStoreSqlConcat {
    public String convertFilter(String key, String value) {
        // VULNERABLE: user-controlled filter values in SQL
        return String.format("metadata ->> '%s' = '%s'", key, value);
    }
}
