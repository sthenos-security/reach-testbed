# REACHABLE Testbed Validation

Automated validation that REACHABLE detects all expected findings in this testbed.

## How it works

1. `testbed.json` — declares what the scanner **must** find (the baseline)
2. `validate.py` — diffs scanner output against the baseline, exits non-zero on any miss
3. `.github/workflows/validate.yml` — manual GitHub Actions workflow

## Running locally

```bash
# Scan the testbed
reachctl scan /path/to/reach-testbed --ci --fail-on none

# Export SARIF
reachctl export --format sarif --repo /path/to/reach-testbed --output scan-results.sarif

# Validate against baseline
python validate.py --sarif scan-results.sarif

# Or validate directly against repo.db
python validate.py --db ~/.reachable/scans/reach-testbed-*/repo.db

# Verbose output (show all findings)
python validate.py --sarif scan-results.sarif --verbose
```

## Updating the baseline

When you add new test cases or improve detection:

```bash
# See what the scanner currently finds
python validate.py --db ~/.reachable/scans/reach-testbed-*/repo.db --update-baseline

# Then manually edit testbed.json to add new expected entries
# Then run validate.py to confirm the new entries pass
```

## Output

```
CVE
────────────────────────────────────────────────────────────
  ✔ PASS  CVE-2022-42969  pkg=pypdf reach=REACHABLE
  ✔ PASS  CVE-2020-14343  pkg=pyyaml reach=NOT_REACHABLE

CWE
────────────────────────────────────────────────────────────
  ✔ PASS  CWE-89  file=cwe-tests/python/cwe_injection.py
  ✘ MISS  CWE-22  Not found (file=cwe-tests/python/cwe_path_traversal.py)

══════════════════════════════════════════════════════════════
  5 passed  1 missing  0 warnings
══════════════════════════════════════════════════════════════

✘ TESTBED VALIDATION FAILED — 1 expected finding(s) not detected
```

## CI workflow

The workflow runs manually from GitHub Actions → `Testbed Validation`.

Inputs:
- `reachable_version` — pin to a specific version or use `latest`
- `fail_on` — severity gate (default: `high`)
- `verbose` — show all findings in validator output

Requires secrets:
- `REACH_CORE_PAT` — GitHub PAT with access to reach-dist
- `REACHABLE_LICENSE` — license key
