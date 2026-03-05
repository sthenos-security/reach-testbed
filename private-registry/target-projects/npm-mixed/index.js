/**
 * npm mixed registry demo app.
 * 
 * Imports from both public (express, lodash) and private (@company/*)
 * packages so reachctl has real code paths to trace.
 */
const express = require('express');
const _ = require('lodash');
const logger = require('@company/logger');
const http = require('@company/http');
const utils = require('@company/internal-utils');

const app = express();

app.get('/health', (req, res) => {
  logger.info('Health check');
  res.json({ status: 'ok' });
});

app.get('/proxy', async (req, res) => {
  // Exercises @company/http (wraps axios — potential CVE path)
  try {
    const resp = await http.get(req.query.url || 'https://httpbin.org/get');
    res.json(resp.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/format', (req, res) => {
  // Exercises lodash (CVE target) + @company/internal-utils (genuine private)
  const id = utils.formatId(req.query.id || '12345');
  const merged = _.merge({}, { formatted: id }, { timestamp: Date.now() });
  res.json(merged);
});

app.get('/validate', (req, res) => {
  const token = req.headers.authorization || '';
  const valid = utils.validateToken(token);
  res.json({ valid });
});

if (require.main === module) {
  app.listen(3000, () => console.log('Listening on :3000'));
}

module.exports = app;
