# REACHABLE Signal Inventory & Competitor Comparison

> Reference: `expected-results/full-scan-v5.1.3.json` (reach-testbed @ 2943c74e)  
> Purpose: Pre-release validation baseline + sales/investor comparison tool

---

## Signal Priority Tiers

| Priority | Tier | Rationale |
|----------|------|-----------|
| P0 | CRITICAL blocker | Reachable exploit path, high EPSS, CISA KEV or active exploit |
| P1 | Must fix | Reachable, HIGH severity, or REACHABLE secret/PII |
| P2 | Should fix | REACHABLE MEDIUM, or UNKNOWN (can't rule out path) |
| P3 | Backlog | NOT_REACHABLE — no call path found; deprioritise |
| P4 | Informational | Config/IaC control-plane findings |

---

## Signal Inventory (reach-testbed full scan baseline)

| Signal | Total | REACHABLE | NOT_REACHABLE | UNKNOWN | CRIT | HIGH | MED | LOW | Priority |
|--------|------:|----------:|--------------:|--------:|-----:|-----:|----:|----:|----------|
| **CVE** | 46 | 27 | 19 | 0 | 3 | 16 | 25 | 2 | P0–P1 |
| **SECRET** | 119 | 36 | 0 | 83 | 61 | 30 | 28 | 0 | P0–P1 |
| **CWE** | 262 | 1 | 261 | 0 | 90 | 0 | 153 | 19 | P1–P2 |
| **DLP** | 33 | 33 | 0 | 0 | 7 | 10 | 16 | 0 | P0–P1 |
| **AI** | 129 | 86 | 43 | 0 | 0 | 0 | 129 | 0 | P1–P2 |
| **MALWARE** | 19 | 0 | 0 | 19 | 11 | 8 | 0 | 0 | P0 |
| **IAC/CONFIG** | 4 | 0 | 0 | 4 | 0 | 2 | 1 | 1 | P4 |
| **SANDBOX** | 0 | — | — | — | — | — | — | — | P0 (when triggered) |
| **TOTAL** | **612** | **183** | **323** | **106** | **172** | **66** | **352** | **22** | — |

> **Noise reduction: 54.7%** — 183 REACHABLE out of 612 total findings.  
> Excludes IAC/CONFIG from noise funnel (control-plane, not app execution path).

---

## Reachability Coverage by Signal

| Signal | Reachability Applied? | Notes |
|--------|-----------------------|-------|
| CVE | ✅ Full (call graph) | Python/JS/Go/Java call graphs; EPSS + KEV enrichment |
| SECRET | ✅ Partial (import graph) | REACHABLE if secret flows into called function; UNKNOWN if module imported but function not traced |
| CWE | ✅ Full (call graph) | SAST findings mapped to call graph; 261/262 currently NOT_REACHABLE in testbed |
| DLP | ✅ Full (taint + call graph) | All 33 findings REACHABLE in testbed (taint flows to sinks) |
| AI | ✅ Full (call graph) | LLM API calls traced from HTTP entrypoints |
| MALWARE | ⚠️ Static only | GuardDog + YARA; no call-path tracing yet; all UNKNOWN |
| IAC/CONFIG | ❌ N/A | Control-plane; reachability not meaningful |
| SANDBOX | ✅ Dynamic | Runtime detonation; REACHABLE if executed in sandbox |

---

## Competitor Coverage Matrix

| Signal | REACHABLE | Snyk | Trivy | Grype | Semgrep | Checkmarx | SonarQube | Endor Labs |
|--------|:---------:|:----:|:-----:|:-----:|:-------:|:---------:|:---------:|:----------:|
| CVE (SCA) | ✅ + reach | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ + reach |
| CVE reachability | ✅ | ⚠️ partial | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| SECRET | ✅ + reach | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| Secret reachability | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CWE / SAST | ✅ + reach | ⚠️ limited | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| CWE reachability | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ partial | ❌ | ❌ |
| DLP / PII | ✅ + reach | ❌ | ❌ | ❌ | ⚠️ rules only | ⚠️ rules only | ❌ | ❌ |
| DLP taint tracking | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ partial | ❌ | ❌ |
| AI / LLM security | ✅ | ❌ | ❌ | ❌ | ⚠️ rules only | ❌ | ❌ | ❌ |
| AI reachability | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MALWARE (static) | ✅ | ❌ | ✅ | ⚠️ limited | ❌ | ❌ | ❌ | ⚠️ limited |
| MALWARE (dynamic) | ✅ sandbox | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| IAC / Config | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ⚠️ | ❌ |
| Supply chain (SBOM) | ✅ | ✅ | ✅ | ✅ | ❌ | ⚠️ | ❌ | ✅ |
| EPSS enrichment | ✅ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CISA KEV | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Multi-signal correlation | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

> ✅ Full support · ⚠️ Partial/limited · ❌ Not supported

---

## Noise Reduction Comparison (CVE only, representative apps)

| Testcase | Language | Raw CVEs | REACHABLE | Noise reduced | Tool comparison |
|----------|----------|--------:|----------:|--------------:|----------------|
| `python-app` | Python | 47 | 3 | **93.6%** | Snyk/Trivy: all 47 flagged |
| `go-app` | Go | 23 | 2 | **91.3%** | Grype: all 23 flagged |
| `javascript-app` | JS | 156 | 9 | **94.2%** | npm audit: 312 flagged |
| `noisy-enterprise-app` | JS | 283 | 11 | **96.1%** | Trivy: 283, Snyk: 267 |
| `reach-testbed` (full) | Multi | 46 | 27 | **41.3%** | *(testbed intentionally noisy)* |

---

## Signal Detection Counts by Language (signal-matrix testbed)

Expected detections when scanning `signal-matrix/`:

| Signal | Python | JS | Go | Java | Total cells |
|--------|-------:|---:|---:|-----:|------------:|
| CVE | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| CWE | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| SECRET | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| DLP | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| AI | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 3 (R/NR/U) | 12 |
| MALWARE | 2 (R/NR) | 2 (R/NR) | 2 (R/NR) | 1 (NR) | 7 |
| **TOTAL** | **17** | **17** | **17** | **16** | **67** |

R=REACHABLE · NR=NOT_REACHABLE · U=UNKNOWN

A competitor scanning `signal-matrix/` and treating all findings as equally urgent would report
the same raw count but with **zero reachability differentiation** — every REACHABLE, UNKNOWN,
and NOT_REACHABLE finding would be collapsed into a single undifferentiated list.

---

## Severity × Reachability Priority Matrix

Use this to triage scan output:

| Severity | REACHABLE | UNKNOWN | NOT_REACHABLE |
|----------|-----------|---------|---------------|
| **CRITICAL** | 🔴 P0 — fix now | 🟠 P1 — investigate | ⚪ P3 — backlog |
| **HIGH** | 🔴 P0 — fix now | 🟠 P1 — investigate | ⚪ P3 — backlog |
| **MEDIUM** | 🟡 P2 — sprint | 🟡 P2 — sprint | ⚪ P3 — backlog |
| **LOW** | 🟢 P3 — backlog | 🟢 P3 — backlog | ⚪ P4 — ignore |

---

## What Competitors Cannot Do

| Capability | REACHABLE | Any other single tool |
|------------|:---------:|:---------------------:|
| CVE + SECRET + CWE + DLP + AI + MALWARE in one scan | ✅ | ❌ |
| Reachability across ALL signal types | ✅ | ❌ |
| Multi-signal correlation (e.g. CWE + DLP = HIPAA violation) | ✅ | ❌ |
| PII taint tracking to LLM API sinks | ✅ | ❌ |
| Dynamic sandbox + static correlation | ✅ | ❌ |
| Single risk score across all signals | ✅ | ❌ |
| Supply chain package health scoring | ✅ | ❌ |

---

*Last updated: 2026-03-10 · Baseline: reach-testbed @ 2943c74e · v5.1.3*
