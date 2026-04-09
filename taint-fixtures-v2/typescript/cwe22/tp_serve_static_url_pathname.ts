// Fixture: CWE-22 Path Traversal - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: path_join_url_pathname_no_validation
// SOURCE: http_request URL pathname
// SINK: path.join to fs.readFile
// TAINT_HOPS: 2
// NOTES: OAuth callback serves static files using req URL pathname
// REAL_WORLD: microsoft/vscode extensions/github-authentication/src/node/authServer.ts
import * as path from 'path';
import * as fs from 'fs';
import * as http from 'http';
import { URL } from 'url';

const SERVE_ROOT = '/app/static';

function handleRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    const reqUrl = new URL(req.url!, 'http://localhost');
    // VULNERABLE: pathname like /../../../etc/passwd escapes serve root
    const filePath = path.join(SERVE_ROOT, reqUrl.pathname.substring(1));
    fs.readFile(filePath, (err, data) => {
        res.end(data);
    });
}
