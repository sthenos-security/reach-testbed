// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// CWE-79 (Reflected XSS, Stored XSS, DOM XSS)
// ===========================================================================
const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── REACHABLE: CWE-79 — Reflected XSS ────────────────────────────────────
app.get('/search', (req, res) => {
    const query = req.query.q;
    // BAD: User input reflected directly in HTML response
    res.send(`<html><body><h1>Results for: ${query}</h1></body></html>`);
});

app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<div>Welcome back, ${name}!</div>`);
});

app.get('/error', (req, res) => {
    const msg = req.query.message;
    res.send(`<div class="alert alert-danger">${msg}</div>`);
});

// ── REACHABLE: CWE-79 — Stored XSS ──────────────────────────────────────
const comments = [];
app.post('/api/comments', (req, res) => {
    const comment = req.body.comment;
    const author = req.body.author;
    // BAD: Storing raw user HTML, will be rendered unsanitized
    comments.push({ author, comment, html: `<div><b>${author}</b>: ${comment}</div>` });
    res.json({ stored: true });
});

app.get('/api/comments', (req, res) => {
    // Returns raw HTML comments — XSS when rendered
    const html = comments.map(c => c.html).join('');
    res.send(`<html><body>${html}</body></html>`);
});

// ── REACHABLE: CWE-79 — DOM XSS via innerHTML ───────────────────────────
app.get('/profile', (req, res) => {
    res.send(`
        <html><body>
        <div id="bio"></div>
        <script>
            const params = new URLSearchParams(window.location.search);
            document.getElementById('bio').innerHTML = params.get('bio');
        </script>
        </body></html>
    `);
});

app.get('/dashboard', (req, res) => {
    res.send(`
        <html><body>
        <div id="welcome"></div>
        <script>
            const hash = window.location.hash.substr(1);
            document.getElementById('welcome').innerHTML = decodeURIComponent(hash);
        </script>
        </body></html>
    `);
});

// ── REACHABLE: Header injection ──────────────────────────────────────────
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});

app.get('/api/download', (req, res) => {
    const filename = req.query.name;
    // BAD: User controls Content-Disposition header
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send('file content');
});

// ── UNREACHABLE ──────────────────────────────────────────────────────────
function deadXss() {
    const evil = '<script>alert(document.cookie)</script>';
    return `<div>${evil}</div>`;
}

app.listen(4002);
module.exports = app;
