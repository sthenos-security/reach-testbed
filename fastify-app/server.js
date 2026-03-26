/**
 * Fastify application — entrypoint.
 *
 * Plugins registered via fastify.register() are REACHABLE.
 * Routes registered directly are REACHABLE.
 * Plugins/routes in dead/ that are never registered are NOT_REACHABLE.
 */
const fastify = require('fastify')({ logger: true });
const mergeRoutes = require('./routes/merge');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');  // imported but NEVER registered — Type A

// NOTE: dead/dead-plugin.js is NEVER required or registered — NOT_REACHABLE (Type C).
// NOTE: adminRoutes IS required above but never fastify.register()'d — NOT_REACHABLE (Type A).

// Register live plugins (REACHABLE)
fastify.register(mergeRoutes, { prefix: '/api' });
fastify.register(authRoutes, { prefix: '/api' });
// adminRoutes deliberately NOT registered — Type A dead code

// Direct route (REACHABLE)
fastify.get('/api/health', async (request, reply) => {
  return { status: 'ok', framework: 'fastify' };
});

const start = async () => {
  await fastify.listen({ port: 3000 });
};
start();
