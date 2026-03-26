/**
 * Dead plugin — NOT_REACHABLE.
 *
 * This plugin is defined but NEVER registered via fastify.register() in server.js.
 * All findings here should be NOT_REACHABLE.
 */
const serialize = require('node-serialize');
const _ = require('lodash');

// SECRET: Dead database URL (NOT_REACHABLE — plugin never registered)
const DEAD_DB_URL = 'postgresql://admin:SuperSecret@db.internal:5432/prod';

async function deadPlugin(fastify, options) {
  fastify.post('/dead-deserialize', async (request, reply) => {
    /** CVE-2017-5941 (node-serialize) — NOT_REACHABLE: plugin not registered. */
    const obj = serialize.unserialize(request.body.data);
    return obj;
  });

  fastify.post('/dead-merge', async (request, reply) => {
    /** CVE-2021-23337 (lodash) — NOT_REACHABLE: plugin not registered. */
    return _.merge({}, request.body);
  });
}

module.exports = deadPlugin;
