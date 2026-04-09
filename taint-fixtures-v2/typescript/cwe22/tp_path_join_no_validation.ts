// Fixture: code_patch · CWE-22 Path Traversal · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: path_join_unvalidated_user_input
// SOURCE: function_parameter
// SINK: fs.readFileSync
// TAINT_HOPS: 1
// NOTES: path.join with unvalidated relative path — classic traversal
import * as path from 'path';
import * as fs from 'fs';

export function openFile(baseDir: string, relativeFile: string): Buffer {
    // VULNERABLE: relativeFile can contain ../
    const filePath = path.join(baseDir, relativeFile);
    return fs.readFileSync(filePath);
}
