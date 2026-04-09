// Fixture: code_patch · CWE-89 SQL Injection · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: hardcoded_schema_insert
// SOURCE: none (literal string)
// SINK: sqlite.exec
// TAINT_HOPS: 0
// NOTES: VSCode-style — fully hardcoded INSERT for schema initialization
// REAL_WORLD: microsoft/vscode src/vs/platform/storage/common/storageService.ts
export function initializeSchema(db: any): void {
    db.exec(`
        INSERT INTO workspace_settings (key, value) VALUES ('defaults', '{}');
        INSERT INTO workspace_settings (key, value) VALUES ('extensions', '[]');
    `);
}
