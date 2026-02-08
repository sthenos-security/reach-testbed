# 🐍 Muad'Dib Simulation

> **⚠️ SECURITY TEST PACKAGE** - This is a safe simulation of a Python/pip supply chain attack for demonstrating REACHABLE's sandbox and static detection capabilities.

## Overview

This package simulates a **malicious setup.py** attack — the Python equivalent of npm postinstall hooks. When `pip install` runs, `setup.py` executes arbitrary Python code via `cmdclass` override, harvesting credentials and exfiltrating them to a C2 server.

This is the exact pattern used by real PyPI malware: `ultrarequests`, `colourama`, `python3-dateutil` (fake), `ctx`, and hundreds of other PyPI infostealers.

## Why This Demo Matters

**The Problem**: Traditional tools see fragments or nothing:
- Semgrep finds "exec(base64.b64decode(...))" (CWE-94, but is it malicious?)
- GuardDog finds "cmd-overwrite" (high false positive for native extensions)
- Trivy/Grype find **nothing** (no CVEs = no detection)

**The Solution**: REACHABLE correlates static + dynamic:
- Static: GuardDog + Semgrep flag suspicious patterns
- **Dynamic sandbox**: `pip install` runs setup.py → honeypots detect credential theft, network monitor catches exfil attempt
- Verdict: **MALICIOUS — BLOCK INSTALLATION**

## Attack Chain

```
pip install muaddib-simulation
         │
         ▼
[setup.py] ──► cmdclass override (MaliciousInstall.run)
         │
         ▼
exec(base64.b64decode(_PAYLOAD))
         │
         ├──► harvest_credentials()
         │       • ~/.aws/credentials
         │       • ~/.ssh/id_rsa, id_ed25519
         │       • ~/.npmrc, ~/.pypirc
         │       • ~/.docker/config.json
         │       • ~/.kube/config
         │
         ├──► harvest_env_vars()
         │       • AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
         │       • GITHUB_TOKEN, NPM_TOKEN, PYPI_TOKEN
         │       • DATABASE_URL, SECRET_KEY
         │
         └──► exfiltrate()
                 • POST to c2.muaddib-attack.test
                 • Fallback: DNS exfil to dns-exfil.muaddib.test
```

## Files

| File | Purpose |
|------|---------|
| `setup.py` | **THE ATTACK** — cmdclass override + base64 payload |
| `muaddib/__init__.py` | Decoy — looks like a legitimate utility library |
| `expected/*.json` | Expected results from each tool and sandbox |
| `run-comparison.sh` | Demo comparison script |

## Detection: Static vs Dynamic

### Static Analysis (GuardDog + Semgrep)

| Signal | Tool | Severity | Actionable alone? |
|--------|------|----------|-------------------|
| `cmdclass` override | GuardDog | MEDIUM | ❌ Many legit packages use this (numpy, cython) |
| `exec(base64.b64decode(...))` | Semgrep (CWE-94) | HIGH | ⚠️ Suspicious but not confirmed malicious |
| SSL verification disabled | Semgrep (CWE-295) | MEDIUM | ❌ Common in dev tools |
| Hardcoded C2 URLs | Semgrep (CWE-798) | LOW | ❌ Could be any URL |
| Sensitive file paths | Semgrep (CWE-22) | MEDIUM | ❌ Legitimate backup tools do this |

**Problem**: Each signal alone has a high false positive rate. You can't block `pip install numpy` because it uses `cmdclass`.

### Dynamic Sandbox (DevNull Jail)

| Signal | Detection Method | Severity | Proof |
|--------|-----------------|----------|-------|
| Reads `~/.aws/credentials` | Honeypot file access | CRITICAL | Credential theft attempt |
| Reads `~/.ssh/id_rsa` | Honeypot file access | CRITICAL | SSH key theft |
| Reads `~/.npmrc` | Honeypot file access | CRITICAL | Token theft |
| Accesses `AWS_ACCESS_KEY_ID` | Environment shim | HIGH | Env var harvesting |
| POST to `c2.muaddib-attack.test` | Network blocked | HIGH | Exfiltration attempt |
| DNS query to `dns-exfil.muaddib.test` | Network blocked | HIGH | Exfil fallback |

**Key insight**: The **exfil chain** (sensitive read + outbound attempt) upgrades verdict from SUSPICIOUS to **MALICIOUS**.

## Sandbox Test

```bash
# Build sandbox image
cd ~/src/reach-core/sandbox
docker build -t reachable/sandbox:latest .

# Test muaddib in sandbox (pip ecosystem, local package)
reachctl sandbox test --local ./muaddib-simulation --ecosystem pip

# Expected: MALICIOUS verdict — honeypot access + network exfil
```

## Quick Demo

```bash
# Show expected results comparison
./run-comparison.sh

# Run with actual tools (requires semgrep, guarddog, reachctl)
./run-comparison.sh --full
```

## Safety

This simulation is **safe for testing**:
- Uses `.test` TLD domains (RFC 2606 — guaranteed not to resolve)
- Credentials in honeypot files are fake (planted by sandbox container)
- Marked with clear `⚠️ TEST ONLY` warnings
- setup.py payload truncates file reads to 100 chars and masks env var values
- All network requests will fail (`.test` domains + sandbox network isolation)

## Comparison: npm (Shai-Hulud) vs pip (Muad'Dib)

| Aspect | Shai-Hulud (npm) | Muad'Dib (pip) |
|--------|-----------------|----------------|
| Entry point | `package.json` → `postinstall` | `setup.py` → `cmdclass` override |
| Execution trigger | `npm install` | `pip install` |
| Obfuscation | Base64 module paths | Base64 `exec()` payload |
| Credential targets | Same (AWS, SSH, npm, Docker, K8s) | Same |
| Exfiltration | HTTPS + DNS fallback | HTTPS + DNS fallback |
| Anti-sandbox | Checks CI/DOCKER env vars | None (real attacks check too) |
| Sandbox detection | Go shims + honeypots | Go shims + honeypots |

Both attack patterns are identical in intent — the only difference is the entry mechanism (`postinstall` vs `cmdclass`).

## References

- [PyPI Malware: ultrarequests](https://blog.phylum.io/) — AWS credential theft via setup.py
- [PyPI Malware: ctx](https://www.bleepingcomputer.com/) — Env var theft via __init__.py
- [Python Packaging: cmdclass](https://setuptools.pypa.io/en/latest/userguide/extension.html) — Legitimate use
- [Dune (Frank Herbert)](https://en.wikipedia.org/wiki/Dune_(novel)) — Muad'Dib, the desert mouse
