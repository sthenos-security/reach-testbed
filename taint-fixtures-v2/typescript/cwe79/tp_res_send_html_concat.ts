// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: express_res_send_html_concat
// SOURCE: http_request (req.query)
// SINK: res.send (HTML string concat)
// TAINT_HOPS: 1
import { Request, Response } from 'express';

export function greetUser(req: Request, res: Response): void {
  const name = req.query.name as string;
  // VULNERABLE: CWE-79 · HTML response with unescaped user input
  res.send(`<h1>Hello, ${name}!</h1>`);
}
