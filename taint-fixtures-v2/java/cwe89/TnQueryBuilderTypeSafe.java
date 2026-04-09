// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: query_builder_type_safe
// SOURCE: function_parameter
// SINK: query_builder
// TAINT_HOPS: 1
// NOTES: Elasticsearch-style typed query builder — no string concat
// REAL_WORLD: elastic/elasticsearch xpack/plugin/sql Querier.java
public class TnQueryBuilderTypeSafe {
    // Simulated typed query builder
    public Object buildQuery(String field, Object value) {
        // SAFE: structured query builder, no string concatenation
        // Equivalent to QueryBuilders.termQuery(field, value)
        return new Object[] { "term", field, value };
    }
}
