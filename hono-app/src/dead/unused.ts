/**
 * Dead routes — NOT_REACHABLE.
 *
 * This file defines Hono routes but is NEVER imported in index.ts.
 * All findings here should be NOT_REACHABLE.
 */
import { Hono } from 'hono';
import * as serialize from 'node-serialize';

const deadRoutes = new Hono();

// SECRET: Dead credential (NOT_REACHABLE — routes never mounted)
const DEAD_ADMIN_TOKEN = 'ghp_deadDeadDeadDeadDeadDeadDeadDeadDead';

deadRoutes.post('/dead-deserialize', async (c) => {
  /** CVE-2017-5941 (node-serialize) — NOT_REACHABLE: never mounted. */
  const body = await c.req.text();
  return c.json(serialize.unserialize(body));
});

deadRoutes.get('/dead-admin', (c) => {
  /** SECRET — NOT_REACHABLE: never mounted. */
  return c.json({ token: DEAD_ADMIN_TOKEN });
});

export { deadRoutes };
