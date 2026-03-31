/**
 * AXIOS-DROPPER SIMULATION
 * ⚠️ TEST ONLY — mirrors axios@1.14.1 supply chain attack
 *
 * Attack pattern:
 *   axios@1.14.1 itself has NO postinstall script — it's clean.
 *   The attack is in its dependency plain-crypto-js@4.2.1 which
 *   runs a postinstall RAT dropper automatically during npm install.
 *
 * This is the exact pattern — legitimate package, malicious transitive dep.
 */
'use strict';

module.exports = {
  get:    (url, config) => Promise.resolve({ data: {}, status: 200, headers: {} }),
  post:   (url, data, config) => Promise.resolve({ data: {}, status: 200, headers: {} }),
  put:    (url, data, config) => Promise.resolve({ data: {}, status: 200, headers: {} }),
  delete: (url, config) => Promise.resolve({ data: {}, status: 200, headers: {} }),
  request: (config) => Promise.resolve({ data: {}, status: 200, headers: {} }),
  create: (defaults) => module.exports,
  defaults: { headers: { common: {} } },
};
