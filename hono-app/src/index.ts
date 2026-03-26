/**
 * Hono application — entrypoint for Cloudflare Workers / Node.js.
 *
 * Routes mounted via app.route() or app.get/post() are REACHABLE.
 * Routes in dead/ that are never mounted are NOT_REACHABLE.
 */
import { Hono } from 'hono';
import { apiRoutes } from './routes/api';
import { adminRoutes } from './routes/admin';  // imported but NEVER mounted — Type A

// NOTE: dead/unused.ts defines routes but is NEVER imported or mounted (Type C).
// NOTE: adminRoutes IS imported above but never app.route()'d below (Type A).

const app = new Hono();

// Mount live routes (REACHABLE)
app.route('/api', apiRoutes);
// adminRoutes deliberately NOT mounted — Type A dead code

// Direct route (REACHABLE)
app.get('/health', (c) => {
  return c.json({ status: 'ok', framework: 'hono' });
});

// Cloudflare Workers / Node.js export
export default app;
