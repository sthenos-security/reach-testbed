// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: parameterized_query
// SOURCE: function_parameter
// SINK: sqlite.prepare
// TAINT_HOPS: 1
// NOTES: VSCode-style — parameterized query with ? placeholder
// REAL_WORLD: microsoft/vscode src/vs/workbench/api/common/extHostStorage.ts
export function queryUserSettings(db: any, settingKey: string): any {
    // SAFE: parameterized query
    const stmt = db.prepare('SELECT value FROM settings WHERE key = ?');
    return stmt.get(settingKey)?.value ?? null;
}
