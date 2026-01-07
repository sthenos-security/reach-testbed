# Noisy Enterprise App

> **Demo Purpose**: Simulate a typical enterprise Node.js application with heavy dependency tree to demonstrate REACHABLE's noise reduction capabilities.

## The Problem This Demonstrates

```
Traditional Scanner Output:
┌─────────────────────────────────────────────────────┐
│  🔴 283 vulnerabilities found                       │
│     • 23 Critical                                   │
│     • 67 High                                       │
│     • 112 Medium                                    │
│     • 81 Low                                        │
│                                                     │
│  Estimated triage time: 3+ weeks                    │
│  Developer reaction: 😫 "Not this again..."         │
└─────────────────────────────────────────────────────┘
```

## What REACHABLE Shows

```
REACHABLE Output:
┌─────────────────────────────────────────────────────┐
│  🎯 11 REACHABLE vulnerabilities                    │
│     • 3 High (actually exploitable)                 │
│     • 6 Medium                                      │
│     • 2 Low                                         │
│                                                     │
│  272 CVEs filtered (96.1% noise reduction)          │
│  Estimated triage time: 2 hours                     │
│  Developer reaction: 😊 "I can actually fix these!" │
└─────────────────────────────────────────────────────┘
```

## Why So Many Dependencies?

This simulates a real enterprise app pattern:

| Category | Count | Purpose |
|----------|-------|---------|
| Core Framework | 6 | express, cors, helmet, etc. |
| Data/Validation | 8 | lodash, mongoose, validator, etc. |
| Auth | 4 | jwt, bcrypt, passport |
| Cloud SDKs | 4 | aws-sdk, googleapis, firebase |
| Payments/Comms | 3 | stripe, twilio, nodemailer |
| Image Processing | 4 | sharp, jimp, imagemin |
| Date/Time | 5 | moment, dayjs, date-fns, luxon |
| Dev Tools | 30+ | webpack, eslint, jest, babel |
| **Total** | **95+** | Typical enterprise app |

## What the App Actually Uses

Look at `src/index.js` - it only imports **15 packages**:

```javascript
// Actually imported and REACHABLE:
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
// ... ~7 more

// NOT imported (80+ packages):
// - puppeteer, playwright (never used)
// - aws-sdk, googleapis (never used)
// - stripe, twilio (never used)
// - graphql, apollo (never used)
// - all devDependencies (build-time only)
```

## Key Demo Points

### 1. Dev Dependencies = Noise
```
webpack, eslint, jest, babel = 89 CVEs
Production impact: ZERO
REACHABLE: All filtered out
```

### 2. Unused Features = Noise
```
puppeteer, aws-sdk, stripe = 67 CVEs
Installed "just in case" but never imported
REACHABLE: All filtered out
```

### 3. Transitive Dependencies = Noise
```
glob-parent, minimist, ansi-regex = 98 CVEs
Pulled in by other deps, code never reaches them
REACHABLE: All filtered out
```

## Running the Demo

```bash
# Traditional scan (prepare for wall of CVEs)
npm audit
# or
snyk test
# or
trivy fs .

# REACHABLE scan (see the difference)
reachctl scan . --output demo-results/
```

## Expected Results

See `expected-results/noisy-enterprise-app.json` for detailed breakdown:

- **Total CVEs**: 283
- **Reachable CVEs**: 11
- **Noise Reduction**: 96.1%
- **Triage Time Saved**: ~118 hours

## ROI Calculation

| Metric | Traditional | REACHABLE |
|--------|-------------|-----------|
| CVEs to Review | 283 | 11 |
| Hours to Triage | 120 | 2 |
| Cost @ $75/hr | $9,000 | $150 |
| **Savings per Scan** | - | **$8,850** |

With 4 scans/month: **$35,400/month saved**
