/**
 * TypeScript testbed app — REACHABLE testbed
 * Contains reachable CVEs, CWEs, secrets, AI patterns, DLP/PII
 * All vulnerabilities are intentional for scanner validation.
 */

import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import _ from 'lodash';
import xml2js from 'xml2js';
import qs from 'qs';
import semver from 'semver';

const app = express();
app.use(express.json());
app.use(express.text({ type: 'application/xml' }));

// ============================================================================
// HARDCODED SECRETS (SECRET signal)
// ============================================================================

const JWT_SECRET = 'super-secret-jwt-key-hardcoded-do-not-commit-abc123';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const STRIPE_API_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
const GITHUB_TOKEN = 'ghp_16C7e42F292c6912E7710c838347Ae298G5Le';
const SENDGRID_KEY = 'SG.fake.sendgrid.key.for.testing.purposes.only.abcdefghijklmnopqrstuvwxyz';

// ============================================================================
// CVE: CVE-2021-23337 — lodash template command injection (REACHABLE)
// ============================================================================

app.post('/api/render-template', (req: Request, res: Response) => {
  const { template, data } = req.body;
  // REACHABLE: user-controlled template passed directly to _.template
  // CVE-2021-23337: lodash template() allows arbitrary code execution
  const compiled = _.template(template);
  const result = compiled(data);
  res.json({ result });
});

// ============================================================================
// CVE: CVE-2022-23529 — jsonwebtoken algorithm confusion (REACHABLE)
// ============================================================================

app.post('/api/verify-token', (req: Request, res: Response) => {
  const { token } = req.body;
  // REACHABLE: algorithm not explicitly restricted, allows RS256→HS256 confusion
  // CVE-2022-23529: jwt.verify without algorithm restriction
  const decoded = jwt.verify(token, JWT_SECRET);
  res.json({ user: decoded });
});

app.post('/api/issue-token', (req: Request, res: Response) => {
  const { userId, role } = req.body;
  // REACHABLE: token signed with weak hardcoded secret
  const token = jwt.sign({ userId, role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// ============================================================================
// CVE: CVE-2023-0842 — xml2js XXE (REACHABLE)
// ============================================================================

app.post('/api/parse-xml', async (req: Request, res: Response) => {
  const xmlData = req.body as string;
  // REACHABLE: xml2js <=0.4.23 vulnerable to XXE and prototype pollution
  // CVE-2023-0842: explicitArray default can be abused for prototype pollution
  const result = await xml2js.parseStringPromise(xmlData, {
    explicitArray: false,
    // No entity resolver — XXE possible in older versions
  });
  res.json(result);
});

// ============================================================================
// CVE: CVE-2022-24999 — qs prototype pollution (REACHABLE)
// ============================================================================

app.get('/api/search', (req: Request, res: Response) => {
  const rawQuery = req.url.split('?')[1] || '';
  // REACHABLE: qs.parse without allowPrototypes:false allows __proto__ injection
  // CVE-2022-24999: qs <=6.5.2 prototype pollution
  const parsed = qs.parse(rawQuery);
  const results = filterData(parsed as Record<string, string>);
  res.json({ results });
});

function filterData(filters: Record<string, string>): object[] {
  // Simulated DB call using potentially polluted object
  return [{ id: 1, name: 'result', ...filters }];
}

// ============================================================================
// CVE: CVE-2022-25883 — semver ReDoS (REACHABLE — called from request path)
// ============================================================================

app.post('/api/check-version', (req: Request, res: Response) => {
  const { version, range } = req.body;
  // REACHABLE: semver.satisfies on user-controlled input — ReDoS in <=5.7.1
  // CVE-2022-25883: pathological input causes catastrophic backtracking
  const satisfies = semver.satisfies(version, range);
  res.json({ satisfies });
});

// ============================================================================
// CWE: SQL Injection (CWE-089)
// ============================================================================

app.get('/api/user/:id', (req: Request, res: Response) => {
  const userId = req.params.id;
  // CWE-089: String interpolation into SQL — classic injection
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  // Simulated DB execution
  executeSql(query);
  res.json({ query });
});

function executeSql(query: string): void {
  // Simulated — in real app would call pg/mysql
  console.log('Executing:', query);
}

// ============================================================================
// CWE: Command Injection (CWE-078)
// ============================================================================

import { exec } from 'child_process';

app.post('/api/run-tool', (req: Request, res: Response) => {
  const { tool } = req.body;
  // CWE-078: exec with unsanitized user input
  exec(`/usr/local/bin/${tool} --check`, (err, stdout) => {
    if (err) res.status(500).json({ error: err.message });
    else res.json({ output: stdout });
  });
});

// ============================================================================
// CWE: Path Traversal (CWE-022)
// ============================================================================

import path from 'path';
import fs from 'fs';

const BASE_DIR = '/var/app/reports';

app.get('/api/report/:filename', (req: Request, res: Response) => {
  const filename = req.params.filename;
  // CWE-022: Path traversal — no path.resolve or containment check
  const filePath = BASE_DIR + '/' + filename;
  if (fs.existsSync(filePath)) {
    res.send(fs.readFileSync(filePath, 'utf8'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// ============================================================================
// CWE: XSS (CWE-079)
// ============================================================================

app.get('/api/profile', (req: Request, res: Response) => {
  const username = req.query.username as string;
  // CWE-079: Unsanitized user input reflected into HTML response
  res.setHeader('Content-Type', 'text/html');
  res.send(`<html><body><h1>Profile: ${username}</h1></body></html>`);
});

// ============================================================================
// CWE: Weak Crypto (CWE-327)
// ============================================================================

import crypto from 'crypto';

app.post('/api/hash-password', (req: Request, res: Response) => {
  const { password } = req.body;
  // CWE-327: MD5 used for password hashing
  const hash = crypto.createHash('md5').update(password).digest('hex');
  res.json({ hash });
});

// ============================================================================
// CWE: SSRF (CWE-918)
// ============================================================================

import https from 'https';

app.post('/api/fetch-url', (req: Request, res: Response) => {
  const { url } = req.body;
  // CWE-918: User-controlled URL fetched without SSRF protection
  https.get(url, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => res.json({ data }));
  }).on('error', (e) => res.status(500).json({ error: e.message }));
});

// ============================================================================
// CWE: Hardcoded Credentials / Insecure Auth (CWE-798 / CWE-287)
// ============================================================================

const ADMIN_PASSWORD = 'admin123';  // CWE-798

app.post('/api/admin/login', (req: Request, res: Response) => {
  const { password } = req.body;
  // CWE-287: Password comparison without timing-safe compare
  if (password === ADMIN_PASSWORD) {
    res.json({ token: jwt.sign({ admin: true }, JWT_SECRET) });
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

// ============================================================================
// AI SECURITY: Prompt Injection (LLM01)
// ============================================================================

app.post('/api/chat', async (req: Request, res: Response) => {
  const { userMessage, systemPrompt } = req.body;
  // LLM01: User message directly concatenated into system prompt — prompt injection
  const fullPrompt = `${systemPrompt}\n\nUser: ${userMessage}`;
  // Simulated LLM call
  const response = await callLLM(fullPrompt);
  res.json({ response });
});

async function callLLM(prompt: string): Promise<string> {
  // In real app: OpenAI/Anthropic API call
  return `LLM response to: ${prompt.substring(0, 50)}`;
}

app.post('/api/analyze-doc', async (req: Request, res: Response) => {
  const { documentContent } = req.body;
  // LLM01: Document content used unsanitized in prompt — indirect prompt injection
  const prompt = `Analyze this document and summarize key points:\n\n${documentContent}`;
  const analysis = await callLLM(prompt);
  res.json({ analysis });
});

// ============================================================================
// AI SECURITY: Insecure Output Handling (LLM02)
// ============================================================================

app.post('/api/generate-html', async (req: Request, res: Response) => {
  const { request } = req.body;
  const llmOutput = await callLLM(`Generate HTML for: ${request}`);
  // LLM02: LLM-generated HTML injected directly into response without sanitization
  res.setHeader('Content-Type', 'text/html');
  res.send(llmOutput);
});

// ============================================================================
// AI SECURITY: Excessive Agency (LLM06)
// ============================================================================

app.post('/api/ai-execute', async (req: Request, res: Response) => {
  const { task } = req.body;
  const command = await callLLM(`Convert this task to a shell command: ${task}`);
  // LLM06: LLM output used directly as shell command — excessive agency
  exec(command, (err, stdout) => {
    res.json({ output: stdout, error: err?.message });
  });
});

// ============================================================================
// DLP/PII — REAL PII data handled insecurely (various permutations)
// ============================================================================

// PII permutation 1: SSN in plain text log
app.post('/api/onboard', (req: Request, res: Response) => {
  const { name, ssn, dob } = req.body;
  // DLP: SSN logged to console — PII exposure in logs
  console.log(`Onboarding user: ${name}, SSN: ${ssn}, DOB: ${dob}`);
  res.json({ status: 'onboarded' });
});

// PII permutation 2: Credit card stored in plain text
interface PaymentRecord {
  customerId: string;
  cardNumber: string;  // DLP: PAN stored plain text
  cvv: string;
  expiry: string;
  amount: number;
}

const paymentStore: PaymentRecord[] = [];

app.post('/api/payment', (req: Request, res: Response) => {
  const { customerId, cardNumber, cvv, expiry, amount } = req.body;
  // DLP: PAN / CVV stored unencrypted in memory (and would be persisted to DB)
  paymentStore.push({ customerId, cardNumber, cvv, expiry, amount });
  // DLP: Full card number returned in response
  res.json({ status: 'charged', last4: cardNumber.slice(-4), full: cardNumber });
});

// PII permutation 3: Healthcare data (HIPAA)
app.post('/api/health-record', (req: Request, res: Response) => {
  const { patientId, diagnosis, medication, insuranceId } = req.body;
  // DLP: PHI in URL path (logged by any web server)
  res.redirect(`/patient/${patientId}/record?diagnosis=${diagnosis}&med=${medication}`);
});

// PII permutation 4: Email + password in response body
app.get('/api/users', (_req: Request, res: Response) => {
  // DLP: Password hashes returned in API response — information exposure
  const users = [
    { id: 1, email: 'john.doe@example.com', password_hash: 'md5:5f4dcc3b5aa765d61d8327deb882cf99', ssn: '123-45-6789' },
    { id: 2, email: 'jane.smith@corp.com', password_hash: 'md5:e99a18c428cb38d5f260853678922e03', ssn: '987-65-4321' },
  ];
  res.json({ users });
});

// PII permutation 5: Passport / national ID in error message
app.post('/api/verify-identity', (req: Request, res: Response) => {
  const { passport, nationalId } = req.body;
  // DLP: PII in error message returned to client
  if (!passport) {
    res.status(400).json({ error: `Missing passport for user with nationalId: ${nationalId}` });
    return;
  }
  res.json({ verified: true });
});

// PII permutation 6: Financial data — bank account
app.post('/api/bank-transfer', (req: Request, res: Response) => {
  const { fromAccount, toAccount, routingNumber, amount } = req.body;
  // DLP: Full account + routing numbers in log
  console.log(`Transfer: ${fromAccount} (routing: ${routingNumber}) -> ${toAccount}: $${amount}`);
  res.json({ status: 'transferred' });
});

// ============================================================================
// DEAD CODE — not reachable from any route (scanner should flag NOT_REACHABLE)
// ============================================================================

function deadCodeVulnFunction(): void {
  // This function is never called — reachability: NOT_REACHABLE
  const deadSecret = 'sk_test_DEAD_CODE_STRIPE_KEY_UNREACHABLE';
  const hash = crypto.createHash('md5').update(deadSecret).digest('hex');
  console.log('dead:', hash);
  exec('ls -la /tmp', () => {});
}

// ============================================================================
// START
// ============================================================================

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`TypeScript testbed running on port ${PORT}`);
});

export { app };
