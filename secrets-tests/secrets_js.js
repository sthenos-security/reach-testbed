/**
 * REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
 * Tests: Semgrep secrets detection — JS/TS specific patterns
 * All credentials are FAKE patterns that match detection rules
 */
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

// ============================================================================
// REACHABLE SECRETS
// ============================================================================

// Firebase credentials
const FIREBASE_API_KEY = "AIzaSyBcdef1234567890-abcdefghijklmno";
const FIREBASE_CONFIG = {
    apiKey: "AIzaSyBcdef1234567890-abcdefghijklmno",
    authDomain: "test-app.firebaseapp.com",
    databaseURL: "https://test-app.firebaseio.com",
    projectId: "test-app-12345",
    storageBucket: "test-app.appspot.com",
    messagingSenderId: "123456789012",
};

// NPM token
const NPM_TOKEN = "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";

// Docker Hub
const DOCKER_PASSWORD = "dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZab";

// Heroku API key
const HEROKU_API_KEY = "12345678-abcd-efgh-ijkl-1234567890ab";

// DigitalOcean token
const DO_TOKEN = "dop_v1_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";

// Supabase
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTYyMDAwMDAwMCwiZXhwIjoxOTM1MDAwMDAwfQ.EXAMPLE";
const SUPABASE_SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjIwMDAwMDAwLCJleHAiOjE5MzUwMDAwMDB9.EXAMPLE";

// Algolia
const ALGOLIA_API_KEY = "abcdef1234567890abcdef1234567890";
const ALGOLIA_ADMIN_KEY = "1234567890abcdef1234567890abcdef";

// Sentry DSN
const SENTRY_DSN = "https://abcdef1234567890@o123456.ingest.sentry.io/1234567";

// Private key inline
const SSH_PRIVATE_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
EXAMPLE_KEY_DATA_NOT_REAL_JUST_PATTERN_MATCHING
-----END OPENSSH PRIVATE KEY-----`;

// Encryption key
const ENCRYPTION_KEY = "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4a39a8b";
const AES_KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');

// Generic password in connection string
const POSTGRES_URL = "postgres://webapp:Pr0duct10nP@ss!@db-prod.internal:5432/maindb";
const AMQP_URL = "amqp://guest:gu3stP@ss@rabbitmq.internal:5672/";

// ============================================================================
// REACHABLE: Routes using secrets
// ============================================================================
app.get('/api/firebase/data', async (req, res) => {
    const resp = await axios.get(
        `${FIREBASE_CONFIG.databaseURL}/data.json?auth=${FIREBASE_API_KEY}`
    );
    res.json(resp.data);
});

app.post('/api/npm/publish', (req, res) => {
    res.json({ token_prefix: NPM_TOKEN.substring(0, 8), action: 'publish' });
});

app.post('/api/deploy/heroku', async (req, res) => {
    await axios.post('https://api.heroku.com/apps', req.body, {
        headers: { Authorization: `Bearer ${HEROKU_API_KEY}`, Accept: 'application/vnd.heroku+json; version=3' }
    });
    res.json({ deployed: true });
});

app.post('/api/dns/create', async (req, res) => {
    await axios.post('https://api.digitalocean.com/v2/domains', req.body, {
        headers: { Authorization: `Bearer ${DO_TOKEN}` }
    });
    res.json({ created: true });
});

app.post('/api/search/index', async (req, res) => {
    await axios.post('https://test-app.algolia.net/1/indexes/items', req.body, {
        headers: { 'X-Algolia-API-Key': ALGOLIA_ADMIN_KEY, 'X-Algolia-Application-Id': 'TESTAPP' }
    });
    res.json({ indexed: true });
});

app.post('/api/encrypt', (req, res) => {
    const crypto = require('crypto');
    const cipher = crypto.createCipheriv('aes-128-cbc', AES_KEY, Buffer.alloc(16, 0));
    let encrypted = cipher.update(req.body.data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ encrypted });
});

app.get('/api/db/status', async (req, res) => {
    // Uses POSTGRES_URL directly
    const { Client } = require('pg');
    const client = new Client({ connectionString: POSTGRES_URL });
    res.json({ url_prefix: POSTGRES_URL.substring(0, 20) });
});

// UNREACHABLE
function _deadFirebase() { return FIREBASE_API_KEY; }
function _deadNpm() { return NPM_TOKEN; }
function _deadSSH() { return SSH_PRIVATE_KEY; }

app.listen(3010, () => console.log('Secrets tests on 3010'));
