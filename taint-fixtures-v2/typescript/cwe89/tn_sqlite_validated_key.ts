// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: validated_input_parameterized
// SOURCE: function_parameter (validated)
// SINK: sqlite.prepare
// TAINT_HOPS: 1
// NOTES: Input validated by regex then used in parameterized query
export function updateSetting(db: any, key: string, value: string): void {
    if (!/^[a-zA-Z0-9.]+$/.test(key)) {
        throw new Error('Invalid setting key');
    }
    const stmt = db.prepare('UPDATE workspace_settings SET value = ? WHERE key = ?');
    stmt.run(value, key);
}
