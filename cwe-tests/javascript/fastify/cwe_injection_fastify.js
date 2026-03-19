// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
// Framework: Fastify
//
// CWE-89  SQL Injection
// CWE-78  OS Command Injection
// CWE-22  Path Traversal
// CWE-918 SSRF
//
// Fastify entrypoint model (different from Express):
//   fastify.get(route, [options], handler)     — inline handler
//   fastify.get(route, { handler: fn })        — options object handler
//   fastify.register(plugin, opts)             — plugin routes REACHABLE
//   fastify.route({ method, url, handler })    — declarative route
//
// Key differences engine must handle vs Express:
//   1. request.query vs req.query (Fastify uses request, not req)
//   2. request.body vs req.body
//   3. fastify.register() plugin system — routes inside plugins ARE reachable
//   4. Inline async handlers (very common in Fastify)
//   5. Schema-validated inputs — typed schema does NOT guarantee safety from injection
// ============================================================================
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const Fastify = require('fastify');
const mysql = require('mysql2/promise');

const fastify = Fastify({ logger: false });


// ─── Direct route handlers ────────────────────────────────────────────────────

fastify.get('/sqli/query', async (request, reply) => {
  /**
   * CWE-89 TP: SQLi via request.query — REACHABLE.
   * Fastify uses `request.query`, not `req.query`.
   */
  const conn = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
  const [rows] = await conn.query(
    `SELECT * FROM users WHERE name = '${request.query.name}'`  // CWE-89 TP
  );
  return rows;
});

fastify.get('/sqli/query-safe', async (request, reply) => {
  /**
   * CWE-89 FP: parameterized query — REACHABLE but safe.
   */
  const conn = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
  const [rows] = await conn.query('SELECT * FROM users WHERE name = ?', [request.query.name]);
  return rows;
});

fastify.post('/sqli/body', async (request, reply) => {
  /**
   * CWE-89 TP: SQLi via request.body — REACHABLE.
   * Even with JSON schema validation, user controls the string value.
   */
  const conn = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
  const [rows] = await conn.query(
    `SELECT * FROM products WHERE category = '${request.body.category}'`  // CWE-89 TP
  );
  return rows;
});

fastify.post('/cmd', {
  // Fastify options-object style handler
  handler: async (request, reply) => {
    /**
     * CWE-78 TP: options-object handler — engine must find handler: fn.
     */
    const out = execSync(request.body.cmd, { encoding: 'utf8' });
    return { output: out };
  }
});

fastify.get('/path', async (request, reply) => {
  /**
   * CWE-22 TP: path traversal via query param — REACHABLE.
   */
  const filename = request.query.file;
  const content = fs.readFileSync(path.join('/srv/files', filename), 'utf8');
  return { content };
});

fastify.post('/ssrf', async (request, reply) => {
  /**
   * CWE-918 TP: SSRF via request.body.url — REACHABLE.
   */
  const axios = require('axios');
  const resp = await axios.get(request.body.url);
  return { status: resp.status };
});

// fastify.route() declarative style — engine must parse this too
fastify.route({
  method: 'GET',
  url: '/sqli/route-object',
  handler: async (request, reply) => {
    /**
     * CWE-89 TP: declarative fastify.route() — REACHABLE.
     */
    const conn = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
    const [rows] = await conn.query(
      `SELECT * FROM orders WHERE status = '${request.query.status}'`  // CWE-89 TP
    );
    return rows;
  }
});


// ─── Plugin — routes inside registered plugins are REACHABLE ─────────────────

async function adminPlugin(fastify, opts) {
  fastify.get('/admin/users', async (request, reply) => {
    /**
     * CWE-89 TP: route inside fastify.register() plugin — REACHABLE.
     * Engine must follow fastify.register(plugin) to find these routes.
     */
    const conn = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
    const [rows] = await conn.query(
      `SELECT * FROM users WHERE role = '${request.query.role}'`  // CWE-89 TP
    );
    return rows;
  });

  fastify.post('/admin/exec', async (request, reply) => {
    /** CWE-78 TP: command injection inside plugin — REACHABLE. */
    const out = execSync(request.body.cmd, { encoding: 'utf8' });
    return { output: out };
  });
}

fastify.register(adminPlugin, { prefix: '/v1' });


// ─── Unregistered plugin — NOT_REACHABLE ─────────────────────────────────────

async function deadPlugin(fastify, opts) {
  fastify.get('/dead/sqli', async (request, reply) => {
    /**
     * NOT_REACHABLE — deadPlugin is never passed to fastify.register().
     */
    const conn = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });
    await conn.query(`SELECT * FROM secrets WHERE key = '${request.query.key}'`);
    return {};
  });
}
// deadPlugin intentionally NOT registered


// ─── Plain function — NOT_REACHABLE ──────────────────────────────────────────

function unroutedHandler(name) {
  /** NOT_REACHABLE — plain function, no route, never called from a route. */
  const mysql = require('mysql2');
  const pool = mysql.createPool({ host: 'localhost', user: 'root', database: 'app' });
  pool.query(`SELECT * FROM users WHERE name = '${name}'`);
}


module.exports = { fastify };
