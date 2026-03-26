/**
 * Auth routes — REACHABLE (registered via fastify.register in server.js).
 *
 * CVE-2022-23529 (jsonwebtoken) — REACHABLE: jwt.verify called.
 * UNKNOWN: lodash imported but only safe _.pick() used (not vulnerable _.merge).
 */
const jwt = require('jsonwebtoken');
const _ = require('lodash');

const JWT_SECRET = 'fastify-testbed-jwt-secret';

async function authRoutes(fastify, options) {
  fastify.post('/verify', async (request, reply) => {
    /**
     * POST /api/verify — REACHABLE.
     * CVE-2022-23529: jwt.verify with algorithm confusion.
     */
    const token = request.body.token;
    const payload = jwt.verify(token, JWT_SECRET);         // CVE REACHABLE
    return { user: payload };
  });

  fastify.get('/profile', async (request, reply) => {
    /**
     * GET /api/profile — REACHABLE.
     * UNKNOWN: lodash imported, but only safe _.pick() called — not _.merge.
     */
    const user = { name: 'alice', role: 'admin', ssn: '123-45-6789' };
    const safe = _.pick(user, ['name', 'role']);           // UNKNOWN CVE path
    return safe;
  });
}

module.exports = authRoutes;
