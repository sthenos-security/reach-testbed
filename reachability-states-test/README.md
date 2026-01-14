# Reachability States Test Suite

This test directory validates REACHABLE's unified 3-state reachability model across all signal types.

## Purpose

Ensure consistent behavior for all combinations of:
- **Signal Types**: CVE, CWE, SECRET, MALWARE, CONFIG
- **Reachability States**: reachable, not_reachable, unknown

## Test Matrix

| Signal | Reachable | Not Reachable | Unknown |
|--------|-----------|---------------|---------|
| CVE | ✅ `src/cve_reachable.py` | ✅ `src/cve_dead_code.py` | N/A |
| CWE | ✅ `src/cwe_reachable.py` | ✅ `src/cwe_dead_code.py` | ✅ `tests/` (test_only) |
| SECRET | ✅ `src/secret_reachable.py` | ✅ `src/secret_dead_code.py` | ✅ `.env` file |
| CONFIG | N/A | N/A | ✅ `config/Dockerfile`, `config/k8s-deployment.yaml` |
| MALWARE | See `malware-test-packages/` | See `malware-test-packages/` | N/A |

## Directory Structure

```
reachability-states-test/
├── README.md
├── expected-results.json      # Expected scan results for validation
├── requirements.txt           # Vulnerable packages for CVE testing
├── app.py                     # Main entrypoint - imports reachable modules
│
├── src/
│   ├── __init__.py            # Only imports reachable modules
│   ├── cve_reachable.py       # Uses requests (CVE-2021-33503) - IMPORTED
│   ├── cve_dead_code.py       # Uses pyyaml (CVE-2020-14343) - NOT IMPORTED
│   ├── cwe_reachable.py       # XSS/SQLi in called functions - IMPORTED
│   ├── cwe_dead_code.py       # Command injection in dead code - NOT IMPORTED
│   ├── secret_reachable.py    # Hardcoded secrets in used code - IMPORTED
│   └── secret_dead_code.py    # Hardcoded secrets in dead code - NOT IMPORTED
│
├── tests/
│   ├── __init__.py
│   └── test_security.py       # CWEs in test code (test_only state)
│
├── config/
│   ├── Dockerfile             # Container misconfigs (unknown reachability)
│   └── k8s-deployment.yaml    # K8s misconfigs (unknown reachability)
│
└── .env                       # Secrets in config (unknown reachability)
```

## Expected Results

### CVE Signal
- **Reachable**: CVEs in `requests`, `urllib3` (used in `cve_reachable.py`)
- **Not Reachable**: CVEs in `pyyaml` (dead code in `cve_dead_code.py`)

### CWE Signal
- **Reachable**: XSS (CWE-79), SQLi (CWE-89) in `cwe_reachable.py`
- **Not Reachable**: Command Injection (CWE-78) in `cwe_dead_code.py`
- **Test Only**: CWEs in `tests/test_security.py`

### SECRET Signal
- **Reachable**: API keys, AWS creds in `secret_reachable.py` (called from app.py)
- **Not Reachable**: GitHub token, private key in `secret_dead_code.py`
- **Unknown**: All secrets in `.env` file (runtime-loaded)

### CONFIG Signal
- **Unknown**: All Dockerfile and K8s issues (deployment-time, not code execution)

## Running Tests

```bash
# Initialize git repo (required for REACHABLE)
cd reachability-states-test
git init && git add . && git commit -m "test"

# Run REACHABLE scan
reachctl scan . --output results/

# Check results
cat results/dashboard/data.json | jq '.issues[] | {type, id, reachability_state}'
```

## Validation Script

```bash
# Validate expected results
python ../validate.py results/data.json expected-results.json
```

## Key Validation Points

1. **CVEs from imported packages → REACHABLE**
2. **CVEs from unimported packages → NOT_REACHABLE**
3. **CWEs in called functions → REACHABLE**
4. **CWEs in dead code → NOT_REACHABLE**
5. **Secrets in called code → REACHABLE**
6. **Secrets in .env files → UNKNOWN**
7. **CONFIG issues → Always UNKNOWN**
8. **Test code CWEs → test_only or excluded**
