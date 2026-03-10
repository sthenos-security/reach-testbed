'use strict';
/**
 * UNKNOWN: SECRET — module required, only public key returned via safe export.
 * Private key and DB password exist in this module but the functions
 * that return them are never called from server.js.
 */
const PUBLIC_KEY      = 'pk_live_jsUNKNOWN_pub_xxxxxxxxxxx';  // safe — exposed via getPublicKey
const PRIVATE_KEY     = 'sk_live_jsUNKNOWN_xxxxxxxxxxxxxxxxxxx'; // UNKNOWN secret
const DB_PASS_UNKNOWN = 'db_jsUnknown_secret_99999';             // UNKNOWN secret

function getPublicKey() { return PUBLIC_KEY; } // called from server.js — safe

function getPrivateKeyUnknown() { return PRIVATE_KEY; }   // UNKNOWN: never called
function getDbPassUnknown()     { return DB_PASS_UNKNOWN; } // UNKNOWN: never called

module.exports = { getPublicKey, getPrivateKeyUnknown, getDbPassUnknown };
