# Testbed Validation — How to Run

## Overview

The validation system works in three steps:

```
reachctl scan .           →   repo.db  (findings database)
reachctl export --sarif   →   scan-results.sarif  (normalized output)
python validate.py        →   PASS / FAIL with detailed report
```

`testbed.json` declares what the scanner **must** find. `validate.py` diffs the
actual scan output against that baseline and exits non-zero on any miss.

---

## Prerequisites

```bash
# REACHABLE installed and licensed
reachctl --version
reachctl license status

# Python 3.9+
python3 --version
```

---

## Local Run (Recommended)

```bash
cd /Users/alaindazzi/src/reach-testbed

# Step 1: Scan
reachctl scan . --ci --fail-on none

# Step 2: Export SARIF
reachctl export \
  --format sarif \
  --repo . \
  --output scan-results.sarif

# Step 3: Validate
python validate.py --sarif scan-results.sarif
```

### Verbose output (shows all findings including passes)

```bash
python validate.py --sarif scan-results.sarif --verbose
```

### Validate directly against repo.db (faster, more detail)

```bash
python validate.py \
  --db ~/.reachable/scans/reach-testbed-*/repo.db
```

The `--db` flag accepts glob patterns and automatically picks the most recent scan.

---

## Output Legend

```
✔ PASS  — Finding detected with correct reachability
✘ MISS  — Expected finding not detected (scanner regression)
⚠ WARN  — Finding detected but reachability state is wrong
ℹ INFO  — Informational (no action required)
```

Exit code: `0` = all pass, `1` = one or more MISS.

### Sample output

```
CVE
────────────────────────────────────────────────────────────
  ✔ PASS  CVE-2022-42969  pkg=pypdf reach=REACHABLE
  ✔ PASS  CVE-2023-32681  pkg=requests reach=REACHABLE
  ✘ MISS  CVE-2021-33503  Not found (package=urllib3, file=transitive-dep-tests/...)

CVE Group
────────────────────────────────────────────────────────────
  ✔ PASS  Pillow / CVE-2023-44271  reach=REACHABLE
  ✔ PASS  Pillow / CVE-2023-50447  reach=REACHABLE
  ⚠ WARN  cryptography / CVE-2023-49083  reachability=UNKNOWN, expected=REACHABLE

AI
────────────────────────────────────────────────────────────
  ✔ PASS  LLM01  file=ai-security-test/python/llm01_prompt_injection.py
  ✔ PASS  LLM06  file=ai-security-test/python/agentic_security.py
  ✘ MISS  LLM07  Not found (file=ai-security-test/python/llm07_system_prompt_leakage.py)

══════════════════════════════════════════════════════════════
  18 passed  2 missing  1 warning
══════════════════════════════════════════════════════════════

✘ TESTBED VALIDATION FAILED — 2 expected finding(s) not detected
```

---

## What Is Tested

| Category | File(s) | What it validates |
|---|---|---|
| **CVE (direct)** | `python-app/app.py`, `reachability-states-test/` | Scanner finds CVEs and classifies reachability correctly |
| **CVE (transitive depth-1)** | `transitive-dep-tests/` | urllib3 CVE found via requests call chain |
| **CVE (transitive depth-2)** | `transitive-dep-tests/` | urllib3 CVE found via boto3→botocore chain |
| **CVE Groups** | `cve-group-tests/cve_groups.py` | Multiple CVEs per package grouped, mixed reachability |
| **CWE** | `cwe-tests/python/` | SQLi, CMDi, path traversal, weak crypto |
| **Secrets** | `secret-tests/`, `python-app/` | AWS, Stripe, Twilio, SendGrid keys |
| **DLP (static)** | `dlp-tests/dlp_true_positives.py` | SSN, credit card, email detected |
| **DLP (taint)** | `dlp-tests/dlp_taint_flows.py` | PII flowing into LLM API, logs, external HTTP |
| **AI/LLM01** | `llm01_prompt_injection.py` | User input directly in LLM prompt |
| **AI/LLM02** | `llm02_sensitive_disclosure.py` | Sensitive info disclosure |
| **AI/LLM05** | `llm05_output_handling.py` | Insecure output handling |
| **AI/LLM06** | `llm06_excessive_agency.py`, `agentic_security.py` | Excessive agency, tool-call injection |
| **AI/LLM07** | `llm07_system_prompt_leakage.py` | Credentials/PII in system prompt |
| **AI/LLM08** | `agentic_security.py` | RAG poisoning |
| **Agentic** | `agentic_security.py` | eval(LLM output), multi-agent trust, RAG poisoning |
| **Malware** | `static-malware-tests/` | Backdoors, reverse shells, exfil hooks |
| **Reachability** | `reachability-states-test/` | REACHABLE vs NOT_REACHABLE three-state model |

---

## Updating the Baseline

When you add new test cases or the scanner improves detection:

```bash
# See what the scanner currently finds (prints summary, no diff)
python validate.py \
  --db ~/.reachable/scans/reach-testbed-*/repo.db \
  --update-baseline

# Manually add new entries to testbed.json
# Then confirm they pass:
python validate.py --sarif scan-results.sarif
```

Do not use `--update-baseline` to auto-accept regressions — always review the
diff before committing an updated `testbed.json`.

---

## CI — Manual Trigger (GitHub Actions)

1. Go to **Actions** → **Testbed Validation** → **Run workflow**
2. Set inputs:
   - `reachable_version`: pin to a specific version (e.g. `1.0.0b16`) or leave as `latest`
   - `fail_on`: severity gate for the scan step (default: `high`)
   - `verbose`: check for full finding output in logs
3. Download artifacts after run:
   - `scan-results-sarif` — the SARIF from the scan
   - `validation-report` — same SARIF kept for 90 days

### Required secrets

| Secret | Value |
|---|---|
| `REACH_CORE_PAT` | GitHub PAT with read access to `sthenosec/reach-dist` |
| `REACHABLE_LICENSE` | License key string |

---

## Troubleshooting

**All findings are MISS**  
The scan likely failed silently. Check:
```bash
reachctl scan . --ci --fail-on none
echo "Exit: $?"
ls ~/.reachable/scans/reach-testbed-*/repo.db
```

**SARIF is empty**  
Export ran before scan completed, or wrong `--repo` path:
```bash
reachctl export --format sarif --repo /Users/alaindazzi/src/reach-testbed --output scan-results.sarif
python3 -c "import json; d=json.load(open('scan-results.sarif')); print(len(d['runs'][0]['results']), 'results')"
```

**Transitive CVEs all MISS**  
The scanner needs the virtual environment present to resolve transitive deps:
```bash
cd /Users/alaindazzi/src/reach-testbed/transitive-dep-tests
pip install -r requirements.txt
cd ..
reachctl scan . --ci --fail-on none
```

**MISSes on new test files**  
New files not yet in testbed.json. Run `--update-baseline` to see what the
scanner finds, then add entries to `testbed.json` manually.
