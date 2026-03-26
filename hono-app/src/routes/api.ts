/**
 * API routes — REACHABLE (mounted via app.route in index.ts).
 *
 * CVE-2021-23337 (lodash) — REACHABLE: _.merge called.
 * CVE-2022-23529 (jsonwebtoken) — REACHABLE: jwt.verify called.
 * CWE-89 (SQL injection) — REACHABLE: string concat.
 * SECRET — REACHABLE: hardcoded key used in response.
 * UNKNOWN: lodash imported, only safe _.pick() used in /profile.
 */
import { Hono } from 'hono';
import * as _ from 'lodash';
import * as jwt from 'jsonwebtoken';

const apiRoutes = new Hono();

// SECRET: Hardcoded API key (REACHABLE — used in merge response)
const WORKER_API_KEY = 'sk_live_hono_worker_key_testbed';
const JWT_SECRET = 'hono-testbed-jwt-secret';

apiRoutes.post('/merge', async (c) => {
  /**
   * POST /api/merge — REACHABLE.
   * CVE-2021-23337 (lodash prototype pollution): _.merge with user input.
   */
  const body = await c.req.json();
  const merged = _.merge({ role: 'user' }, body);          // CVE REACHABLE
  return c.json({ data: merged, key: WORKER_API_KEY });    // SECRET REACHABLE
});

apiRoutes.post('/verify', async (c) => {
  /**
   * POST /api/verify — REACHABLE.
   * CVE-2022-23529 (jsonwebtoken algorithm confusion).
   */
  const { token } = await c.req.json();
  const payload = jwt.verify(token, JWT_SECRET);            // CVE REACHABLE
  return c.json({ user: payload });
});

apiRoutes.get('/profile', (c) => {
  /**
   * GET /api/profile — REACHABLE.
   * UNKNOWN: lodash imported, only safe _.pick() called.
   */
  const user = { name: 'alice', role: 'admin', ssn: '123-45-6789' };
  return c.json(_.pick(user, ['name', 'role']));           // UNKNOWN CVE path
});

// ═══════════════════════════════════════════════════════════════════
// TYPE B DEAD CODE — function in same file as live routes, never
// called from any route handler.  Module IS imported (via app.route).
// ═══════════════════════════════════════════════════════════════════

import { execSync } from 'child_process';

/** NOT_REACHABLE (Type B): in live module but never called. CWE-78. */
function deadInlineExec(cmd: string): string {
  return execSync(cmd).toString();                          // CWE-78 NOT_REACHABLE (Type B)
}

export { apiRoutes };
