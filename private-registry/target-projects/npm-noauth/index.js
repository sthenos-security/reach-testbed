/**
 * Negative test: npm project WITHOUT private registry auth.
 * express/lodash resolve from public npm.
 * @company/* packages CANNOT be resolved — no Verdaccio auth configured.
 */
const express = require('express');
const _ = require('lodash');

// These imports will fail at runtime because @company packages aren't installed
let logger, http, utils;
try { logger = require('@company/logger'); } catch(e) {}
try { http = require('@company/http'); } catch(e) {}
try { utils = require('@company/internal-utils'); } catch(e) {}

const app = express();
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/format', (req, res) => {
    const merged = _.merge({}, { id: req.query.id }, { ts: Date.now() });
    res.json(merged);
});
module.exports = app;
