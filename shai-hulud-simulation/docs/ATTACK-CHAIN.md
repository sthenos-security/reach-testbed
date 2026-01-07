# Shai-Hulud Attack Chain

> **⚠️ SIMULATION ONLY** - This is a safe recreation of the Shai-Hulud supply chain attack for demonstrating REACHABLE's detection capabilities.

## Attack Overview

**Shai-Hulud** was a sophisticated npm supply chain attack discovered in 2023 that targeted developer credentials, particularly npm tokens. Named after the giant sandworms from Dune, it spread through typosquatting and dependency confusion.

## Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHAI-HULUD ATTACK CHAIN                             │
└─────────────────────────────────────────────────────────────────────────────┘

    Developer runs: npm install <malicious-package>
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 0: ENTRY POINT                                                       │
│  ────────────────────                                                        │
│  package.json → "postinstall": "node lib/loader.js"                         │
│                                                                              │
│  🔍 REACHABLE detects:                                                      │
│     └─ GuardDog: npm-lifecycle-script (postinstall hook)                    │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 1: LOADER (lib/loader.js)                                            │
│  ───────────────────────────────                                             │
│  • Base64-encoded module paths (obfuscation)                                │
│  • Environment detection (anti-sandbox)                                      │
│  • Delayed execution via setTimeout                                          │
│  • Dynamic require() of harvester/exfil modules                              │
│                                                                              │
│  🔍 REACHABLE detects:                                                      │
│     ├─ GuardDog: obfuscated-code (base64 strings)                           │
│     ├─ GuardDog: delayed-execution-pattern                                  │
│     ├─ Semgrep: CWE-94 (code injection via dynamic require)                 │
│     └─ CallGraph: loader.js → harvester.js, exfil.js (REACHABLE)            │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 2: HARVESTER (lib/harvester.js)                                      │
│  ─────────────────────────────────────                                       │
│  Credential Theft:                                                           │
│  • ~/.npmrc (npm tokens) ◄── PRIMARY TARGET                                 │
│  • ~/.ssh/id_rsa (SSH keys)                                                  │
│  • ~/.aws/credentials (AWS creds)                                            │
│  • ~/.docker/config.json                                                     │
│  • Environment variables (NPM_TOKEN, GITHUB_TOKEN, etc.)                     │
│                                                                              │
│  🔍 REACHABLE detects:                                                      │
│     ├─ Semgrep: CWE-22 (path traversal to sensitive files)                  │
│     ├─ Semgrep: secrets-detection (credential file patterns)                │
│     ├─ Semgrep: aws-credentials-exposure                                    │
│     └─ CallGraph: harvester.collect() → REACHABLE from postinstall          │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 3: EXFILTRATION (lib/exfil.js)                                       │
│  ────────────────────────────────────                                        │
│  • Hardcoded C2 domains                                                      │
│  • HTTPS POST with stolen data                                               │
│  • Multiple fallback endpoints                                               │
│  • DNS exfiltration backup                                                   │
│  • Base64 encoding of payload                                                │
│                                                                              │
│  🔍 REACHABLE detects:                                                      │
│     ├─ Semgrep: CWE-798 (hardcoded C2 URLs)                                 │
│     ├─ GuardDog: exfiltration-pattern                                       │
│     ├─ GuardDog: suspicious-http-request                                    │
│     └─ CallGraph: exfil.send() → REACHABLE from postinstall                 │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  ATTACKER C2 SERVER                                                         │
│  ──────────────────                                                          │
│  Receives: npm tokens, SSH keys, AWS creds, GitHub tokens                   │
│  Result: Account takeover, further supply chain compromise                  │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
                          REACHABLE CORRELATION
═══════════════════════════════════════════════════════════════════════════════

Individual tools see fragments. REACHABLE sees the CHAIN:

    postinstall ──REACHABLE──► loader.js ──REACHABLE──► harvester.js
                                    │                        │
                                    │                        ▼
                                    │               [Credential Theft]
                                    │
                                    └──REACHABLE──► exfil.js
                                                        │
                                                        ▼
                                                 [Data Exfiltration]

✅ All malicious code paths are REACHABLE from the entry point
✅ 7+ individual signals correlate to 1 critical finding
✅ Call graph proves the attack chain is exploitable
```

## Why This Matters

### Traditional Tools Miss the Chain

| Tool | What It Sees | What It Misses |
|------|--------------|----------------|
| Semgrep | Individual CWE violations | No reachability context |
| GuardDog | Suspicious patterns | No correlation between stages |
| Trivy | Known CVEs only | ❌ Zero findings (no CVEs) |
| Grype | Known CVEs only | ❌ Zero findings (no CVEs) |

### REACHABLE Sees Everything

1. **Entry Point Identification**: postinstall hook → execution guaranteed
2. **Call Graph Analysis**: All malicious paths traced and verified REACHABLE
3. **Multi-Signal Correlation**: 7 individual alerts → 1 critical finding
4. **Actionable Verdict**: `BLOCK INSTALLATION` with full evidence chain

## Real-World Impact

The actual Shai-Hulud attack:
- Compromised **hundreds of npm packages**
- Stole tokens from **thousands of developers**
- Enabled **cascading supply chain attacks**
- Remained undetected for **weeks**

With REACHABLE, this attack would be detected and blocked **before installation completes**.
