/**
 * Admin plugin — NOT_REACHABLE (Type A).
 *
 * This module IS required in server.js, so its top-level code runs,
 * but it is never passed to fastify.register().  No routes in this
 * plugin are reachable via HTTP.
 *
 * CWE-78 (command injection) — NOT_REACHABLE: plugin never registered.
 * SECRET — NOT_REACHABLE: key defined but endpoint inaccessible.
 */
const { execSync } = require('child_process');

// SECRET: Hardcoded admin token (NOT_REACHABLE — plugin never registered)
const ADMIN_TOKEN = 'adm_live_fastify_9fZ83k';

async function adminRoutes(fastify, options) {
  fastify.post('/admin/exec', async (request, reply) => {
    /** CWE-78 — NOT_REACHABLE (Type A): plugin imported but never registered. */
    return { output: execSync(request.body.cmd).toString() }; // CWE-78 NOT_REACHABLE (Type A)
  });

  fastify.get('/admin/token', async (request, reply) => {
    /** SECRET — NOT_REACHABLE (Type A): endpoint unreachable. */
    return { token: ADMIN_TOKEN };                             // SECRET NOT_REACHABLE (Type A)
  });
}

module.exports = adminRoutes;
