# Tool Comparison Matrix

> Shai-Hulud Detection: Individual Tools vs. REACHABLE

## Executive Summary

| Metric | Individual Tools | REACHABLE |
|--------|------------------|-----------|
| **Total Alerts** | 5-10 scattered | 1 critical |
| **Actionable?** | ❌ Requires manual triage | ✅ Immediate verdict |
| **Attack Chain Visible?** | ❌ Fragments only | ✅ Complete chain |
| **Time to Decision** | Hours (manual analysis) | Seconds |
| **False Positive Risk** | High (no context) | Low (correlated) |

---

## Detailed Tool-by-Tool Analysis

### 🔍 Semgrep (SAST)

**What it finds:**
```
┌────────────────────────────────────────────────────────────────────┐
│ Finding 1: javascript.lang.security.detect-eval-with-expression   │
│ File: lib/loader.js:22                                             │
│ Severity: WARNING                                                  │
│ "Dynamic require() with variable argument"                         │
├────────────────────────────────────────────────────────────────────┤
│ Finding 2: javascript.lang.security.hardcoded-http-url            │
│ File: lib/exfil.js:18-21                                           │
│ Severity: WARNING                                                  │
│ "Hardcoded HTTP/HTTPS URL detected"                                │
├────────────────────────────────────────────────────────────────────┤
│ Finding 3: javascript.lang.security.path-traversal                │
│ File: lib/harvester.js:34-52                                       │
│ Severity: WARNING                                                  │
│ "Potential path traversal with user home directory"                │
└────────────────────────────────────────────────────────────────────┘
```

**What it misses:**
- ❌ No context: Are these code paths ever executed?
- ❌ No correlation: Are these findings related?
- ❌ No entry point analysis: How does execution begin?
- ❌ Buried in 100s of other warnings across codebase

---

### 🐕 GuardDog (Malware Scanner)

**What it finds:**
```
┌────────────────────────────────────────────────────────────────────┐
│ Finding 1: npm-lifecycle-script                                    │
│ File: package.json                                                 │
│ "Package uses postinstall script"                                  │
├────────────────────────────────────────────────────────────────────┤
│ Finding 2: obfuscated-code                                         │
│ File: lib/loader.js                                                │
│ "Base64-encoded strings detected"                                  │
└────────────────────────────────────────────────────────────────────┘
```

**What it misses:**
- ❌ No severity ranking: Is this postinstall malicious or legitimate?
- ❌ No payload analysis: What does the obfuscated code do?
- ❌ High false positives: Many legitimate packages use postinstall

---

### 🔷 Trivy (Vulnerability Scanner)

**What it finds:**
```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│                        (nothing)                                   │
│                                                                    │
│  No known CVEs detected                                            │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

**What it misses:**
- ❌ EVERYTHING - This is a zero-day attack, no CVEs exist
- ❌ CVE-based scanning is blind to novel malware

---

### 🔶 Grype (Vulnerability Scanner)

**What it finds:**
```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│                        (nothing)                                   │
│                                                                    │
│  No known CVEs detected                                            │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

**What it misses:**
- ❌ Same as Trivy - blind to zero-day/novel attacks

---

### 🐍 Snyk (Comprehensive Scanner)

**What it finds:**
```
┌────────────────────────────────────────────────────────────────────┐
│ Finding 1: Hardcoded Secret                                        │
│ File: lib/exfil.js                                                 │
│ Severity: Medium                                                   │
│ "Potential hardcoded URL/credential"                               │
└────────────────────────────────────────────────────────────────────┘
```

**What it misses:**
- ❌ One finding among hundreds of other alerts
- ❌ No attack chain correlation
- ❌ Would require manual investigation

---

## 🚀 REACHABLE (Multi-Signal Correlation)

**What it finds:**
```
╔════════════════════════════════════════════════════════════════════╗
║  🔴 CRITICAL: Supply Chain Attack Detected                        ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  Attack Type: Shai-Hulud Pattern (Credential Theft + Exfil)       ║
║  Confidence: 98%                                                   ║
║  Verdict: BLOCK INSTALLATION                                       ║
║                                                                    ║
╠════════════════════════════════════════════════════════════════════╣
║  ATTACK CHAIN (all paths verified REACHABLE):                     ║
║                                                                    ║
║  [Entry] package.json:postinstall                                  ║
║     │                                                              ║
║     └──► lib/loader.js (Stage 1: Obfuscated Loader)               ║
║            │                                                       ║
║            ├──► lib/harvester.js (Stage 2: Credential Theft)      ║
║            │       • Targets: .npmrc, .ssh/*, .aws/*               ║
║            │       • Harvests: NPM_TOKEN, GITHUB_TOKEN, etc.       ║
║            │                                                       ║
║            └──► lib/exfil.js (Stage 3: Data Exfiltration)         ║
║                    • C2: c2.shai-hulud-attack.test                 ║
║                    • Method: HTTPS POST + DNS fallback             ║
║                                                                    ║
╠════════════════════════════════════════════════════════════════════╣
║  CORRELATED SIGNALS (7):                                          ║
║                                                                    ║
║   1. [GuardDog]  postinstall execution hook                       ║
║   2. [GuardDog]  obfuscated/encoded code patterns                 ║
║   3. [GuardDog]  delayed execution (setTimeout)                   ║
║   4. [Semgrep]   CWE-94: Code injection (dynamic require)         ║
║   5. [Semgrep]   CWE-22: Path traversal (sensitive files)         ║
║   6. [Semgrep]   CWE-798: Hardcoded C2 endpoints                  ║
║   7. [CallGraph] All malicious paths REACHABLE from entry         ║
║                                                                    ║
╠════════════════════════════════════════════════════════════════════╣
║  WHY THIS IS CRITICAL:                                            ║
║                                                                    ║
║  • Entry point WILL execute (postinstall runs on npm install)     ║
║  • All malicious code is REACHABLE from entry                     ║
║  • Attack chain is complete: harvest → exfiltrate                 ║
║  • Targets high-value credentials (npm tokens enable supply       ║
║    chain propagation)                                              ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## Visual Comparison

```
                    FRAGMENTED                         CORRELATED
                   (Individual Tools)                  (REACHABLE)
                   
    Semgrep ──► "hardcoded URL"                    ┌──────────────────┐
                     ↓                              │                  │
              [No Context]                          │   1 CRITICAL     │
                                                    │   FINDING        │
    GuardDog ──► "postinstall"                     │                  │
                     ↓                              │   Complete       │
              [Many False Positives]                │   Attack Chain   │
                                                    │                  │
    Trivy ──► (nothing)                            │   Actionable     │
                     ↓                              │   Verdict        │
              [Blind to Zero-Day]                   │                  │
                                                    └──────────────────┘
    Grype ──► (nothing)                                    ▲
                     ↓                                     │
              [Blind to Zero-Day]                   ───────┴───────
                                                    All signals
                                                    correlated
```

---

## ROI Summary

| Scenario | Individual Tools | REACHABLE |
|----------|------------------|-----------|
| Alert Volume | 5-10 low/medium alerts | 1 critical alert |
| Triage Time | 2-4 hours | 0 minutes |
| Decision Confidence | Low (needs investigation) | High (evidence chain) |
| Attack Blocked? | ❌ Likely missed | ✅ Blocked immediately |
| Developer Friction | High (alert fatigue) | Low (only critical) |

> **Bottom Line**: Individual tools would likely let Shai-Hulud through.  
> REACHABLE blocks it with a single, high-confidence finding.
