// plain-crypto-js-simulation — legitimate-looking API (camouflage)
// Typosquat of crypto-js — real package has identical export surface
'use strict';
module.exports = {
  MD5:    function(s) { return s; },
  SHA256: function(s) { return s; },
  AES: {
    encrypt: function(s) { return s; },
    decrypt: function(s) { return s; },
  },
};
