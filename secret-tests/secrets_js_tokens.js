// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// SECRET: JavaScript API keys, tokens, connection strings
// ===========================================================================
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());

// ── REACHABLE: Firebase config (all keys exposed) ───────────────────────
const FIREBASE_CONFIG = {
    apiKey: "AIzaSyBaBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
    authDomain: "my-app-12345.firebaseapp.com",
    databaseURL: "https://my-app-12345.firebaseio.com",
    projectId: "my-app-12345",
    storageBucket: "my-app-12345.appspot.com",
    messagingSenderId: "123456789012",
};

// ── REACHABLE: Algolia ─────────────────────────────────────────────────
const ALGOLIA_APP_ID = "ABCDEF1234";
const ALGOLIA_ADMIN_KEY = "abcdef1234567890abcdef1234567890";

// ── REACHABLE: Mapbox ──────────────────────────────────────────────────
const MAPBOX_TOKEN = "pk.eyJ1IjoiZXhhbXBsZSIsImEiOiJjazEyMzQ1Njc4OTAifQ.aBcDeFgHiJkLmNoPqRsTu";

// ── REACHABLE: Sentry DSN ──────────────────────────────────────────────
const SENTRY_DSN = "https://abcdef1234567890@o123456.ingest.sentry.io/1234567";

// ── REACHABLE: Mailchimp ───────────────────────────────────────────────
const MAILCHIMP_API_KEY = "abcdef1234567890abcdef1234567890-us1";

// ── REACHABLE: Shopify ─────────────────────────────────────────────────
const SHOPIFY_ACCESS_TOKEN = "shpat_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234";

app.get('/api/search', async (req, res) => {
    const resp = await axios.post(`https://${ALGOLIA_APP_ID}-dsn.algolia.net/1/indexes/products/query`, 
        { query: req.query.q },
        { headers: { 'X-Algolia-API-Key': ALGOLIA_ADMIN_KEY, 'X-Algolia-Application-Id': ALGOLIA_APP_ID } });
    res.json(resp.data);
});

app.get('/api/map/token', (req, res) => {
    res.json({ token: MAPBOX_TOKEN });
});

app.post('/api/subscribe', async (req, res) => {
    await axios.post('https://us1.api.mailchimp.com/3.0/lists/abc123/members',
        { email_address: req.body.email, status: 'subscribed' },
        { auth: { username: 'any', password: MAILCHIMP_API_KEY } });
    res.json({ subscribed: true });
});

app.get('/api/firebase/config', (req, res) => {
    res.json(FIREBASE_CONFIG);
});

function deadSecrets() {
    const OLD_KEY = "sk_test_DEADBEEF";
    const OLD_SENTRY = "https://deadbeef@sentry.io/0";
    return { OLD_KEY, OLD_SENTRY };
}

app.listen(4010);
module.exports = app;
