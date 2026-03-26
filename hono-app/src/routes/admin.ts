/**
 * Admin routes — NOT_REACHABLE (Type A).
 *
 * This module IS imported in index.ts, so top-level code runs,
 * but it is never passed to app.route().  No endpoint is reachable.
 *
 * CWE-78 (command injection) — NOT_REACHABLE: routes never mounted.
 * SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
 */
import { Hono } from 'hono';
import { execSync } from 'child_process';

const adminRoutes = new Hono();

// SECRET: Hardcoded admin token (NOT_REACHABLE — routes never mounted)
const ADMIN_TOKEN = 'adm_live_hono_Xk9Qw3';

adminRoutes.post('/admin/exec', async (c) => {
  /** CWE-78 — NOT_REACHABLE (Type A): imported but never mounted. */
  const { cmd } = await c.req.json();
  return c.json({ output: execSync(cmd).toString() });     // CWE-78 NOT_REACHABLE (Type A)
});

adminRoutes.get('/admin/token', (c) => {
  /** SECRET — NOT_REACHABLE (Type A): endpoint unreachable. */
  return c.json({ token: ADMIN_TOKEN });                   // SECRET NOT_REACHABLE (Type A)
});

export { adminRoutes };
