// Fixture: code_patch · CWE-79 Cross-Site Scripting · TypeScript
// VERDICT: TRUE_NEGATIVE
// PATTERN: dompurify_sanitized_html
// SOURCE: http_request (req.body)
// SINK: res.send (sanitized HTML)
// TAINT_HOPS: 1
// NOTES: DOMPurify sanitizes HTML — removes dangerous elements
import { Request, Response } from 'express';
import DOMPurify from 'dompurify';

export function renderContent(req: Request, res: Response): void {
  const userHtml = req.body.content;
  // SAFE: DOMPurify sanitizes HTML content
  const cleanHtml = DOMPurify.sanitize(userHtml);
  res.send(`<div>${cleanHtml}</div>`);
}
