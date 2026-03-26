/**
 * Merge routes — REACHABLE (registered via fastify.register in server.js).
 *
 * CVE-2021-23337 (lodash prototype pollution) — REACHABLE: _.merge called.
 * CWE-89 (SQL injection) — REACHABLE: string concat.
 * SECRET — REACHABLE: hardcoded API key in response.
 */
const _ = require('lodash');

// SECRET: Hardcoded API key (REACHABLE — used in merge handler response)
const INTERNAL_API_KEY = 'sk_live_fastify_testbed_key_example';

async function mergeRoutes(fastify, options) {
  fastify.post('/merge', async (request, reply) => {
    /**
     * POST /api/merge — REACHABLE.
     * CVE-2021-23337 (lodash): _.merge with user input.
     */
    const base = { role: 'user' };
    const merged = _.merge(base, request.body);            // CVE REACHABLE
    return { data: merged, key: INTERNAL_API_KEY };        // SECRET REACHABLE
  });

  fastify.get('/query', async (request, reply) => {
    /**
     * GET /api/query?q=... — REACHABLE.
     * CWE-89: SQL injection via string concatenation.
     */
    const q = request.query.q || '';
    const sqlite3 = require('better-sqlite3');
    const db = sqlite3(':memory:');
    db.exec('CREATE TABLE IF NOT EXISTS items (name TEXT)');
    const rows = db.prepare(`SELECT * FROM items WHERE name = '${q}'`).all(); // CWE REACHABLE
    return { results: rows };
  });
}

// ═══════════════════════════════════════════════════════════════════
// TYPE B DEAD CODE — function in same file as live plugin routes,
// but never called from any route handler or exported as a route.
// Module IS imported (via fastify.register), but this function is dead.
// ═══════════════════════════════════════════════════════════════════

const { execSync } = require('child_process');

/** NOT_REACHABLE (Type B): helper in live module, never called.
 *  CWE-78 (command injection) — NOT_REACHABLE. */
function deadInlineExec(cmd) {
  return execSync(cmd).toString();                         // CWE-78 NOT_REACHABLE (Type B)
}

module.exports = mergeRoutes;
