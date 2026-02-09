/**
 * Secrets in JavaScript — provider tokens, connection strings, API keys
 * Both REACHABLE (used in routes) and UNREACHABLE (dead code)
 */
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

// REACHABLE SECRETS
const FIREBASE_API_KEY = "AIzaSyBabcdefghijklmnopqrstuvwxyz12345";
const FIREBASE_ADMIN_KEY = '{"type":"service_account","project_id":"my-app","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nMIIEpA...\\n-----END RSA PRIVATE KEY-----\\n"}';
const ALGOLIA_API_KEY = "abcdef0123456789abcdef0123456789";
const ALGOLIA_ADMIN_KEY = "abcdef0123456789abcdef01234567890123456789abcdef";
const SHOPIFY_API_SECRET = "shpss_abcdef0123456789abcdef0123";
const MAPBOX_TOKEN = "pk.eyJ1IjoidGVzdCIsImEiOiJjbGFiY2RlZjAxMjM0NTY3ODlhYmNkZWYifQ.abcdef0123456789";
const SENTRY_DSN = "https://abcdef0123456789@o123456.ingest.sentry.io/1234567";
const CLOUDFLARE_API_TOKEN = "v1.0-abcdef0123456789-abcdef0123456789abcdef0123456789";
const DATADOG_API_KEY = "ddabcdef0123456789abcdef01234567";
const NPM_TOKEN = "npm_ABCDEFGHIJKLMNOPqrstuvwxyz012345";
const DOCKERHUB_TOKEN = "dckr_pat_ABCDEFGHIJKLMNOPqrstuvwxy";
const HEROKU_API_KEY = "abcdef01-2345-6789-abcd-ef0123456789";
const DIGITALOCEAN_TOKEN = "dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const OKTA_CLIENT_SECRET = "abcDEF012-ghiJKL345_mnoPQR678";

// REACHABLE ROUTES
app.get('/api/search', (req, res) => {
    const algoliasearch = require('algoliasearch');
    const client = algoliasearch('APP_ID', ALGOLIA_ADMIN_KEY);
    const index = client.initIndex('products');
    index.search(req.query.q).then(r => res.json(r));
});

app.get('/api/map/geocode', (req, res) => {
    axios.get(`https://api.mapbox.com/geocoding/v5/mapbox.places/${req.query.address}.json?access_token=${MAPBOX_TOKEN}`)
        .then(r => res.json(r.data));
});

app.post('/api/metrics', (req, res) => {
    axios.post('https://api.datadoghq.com/api/v1/series',
        { series: req.body.metrics },
        { headers: { 'DD-API-KEY': DATADOG_API_KEY } })
        .then(() => res.json({ sent: true }));
});

app.post('/api/deploy', (req, res) => {
    axios.post('https://api.heroku.com/apps', req.body, {
        headers: { 'Authorization': `Bearer ${HEROKU_API_KEY}`, 'Accept': 'application/vnd.heroku+json; version=3' }
    }).then(r => res.json(r.data));
});

app.post('/api/error/report', (req, res) => {
    const Sentry = require('@sentry/node');
    Sentry.init({ dsn: SENTRY_DSN });
    Sentry.captureMessage(req.body.message);
    res.json({ reported: true });
});

app.post('/api/shop/products', (req, res) => {
    axios.get('https://myshop.myshopify.com/admin/api/2024-01/products.json', {
        headers: { 'X-Shopify-Access-Token': SHOPIFY_API_SECRET }
    }).then(r => res.json(r.data));
});

app.post('/api/dns/purge', (req, res) => {
    axios.post(`https://api.cloudflare.com/client/v4/zones/${req.body.zone}/purge_cache`,
        { purge_everything: true },
        { headers: { 'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}` } })
        .then(r => res.json(r.data));
});

app.post('/api/auth/sso', (req, res) => {
    axios.post('https://dev-123456.okta.com/oauth2/v1/token', {
        client_id: 'abc123', client_secret: OKTA_CLIENT_SECRET,
        grant_type: 'authorization_code', code: req.body.code
    }).then(r => res.json(r.data));
});

// UNREACHABLE SECRETS
const DEAD_CIRCLECI_TOKEN = "ccipat_abcdef0123456789ABCDEFabcdef0123456789ABCDEF";
const DEAD_GITLAB_TOKEN = "glpat-ABCDEFGHIJKLmnopqrst";
const DEAD_PULUMI_TOKEN = "pul-abcdef0123456789abcdef0123456789abcdef01";

function _deadCircleci() {
    axios.get('https://circleci.com/api/v2/me', { headers: { 'Circle-Token': DEAD_CIRCLECI_TOKEN } });
}
function _deadGitlab() {
    axios.get('https://gitlab.com/api/v4/projects', { headers: { 'PRIVATE-TOKEN': DEAD_GITLAB_TOKEN } });
}

app.listen(4010);
