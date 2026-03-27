# .pth Auto-Execution Simulation (LiteLLM/TeamPCP Pattern)

> **SECURITY TEST PACKAGE** - This is a safe simulation of a .pth file supply chain attack for demonstrating REACHABLE's malware detection capabilities. All exfiltration targets point to localhost. No real credentials are accessed.

## Overview

This package simulates the **LiteLLM/TeamPCP attack** (March 2026) — a compromised PyPI package that ships a `.pth` file which auto-executes at Python interpreter startup, bootstrapping a multi-stage credential harvester.

The `.pth` mechanism is distinct from `setup.py` install hooks:
- `setup.py` hooks run once during `pip install`
- `.pth` files run **every time Python starts** — even if the package is never imported
- Python's `site.py` reads all `.pth` files in `site-packages/` at startup
- Lines starting with `import ` are executed as code

## Attack Chain

```
pip install fake-litellm
         |
         v
[litellm_init.pth] ──> "import litellm_metadata_service"
         |                 (auto-executed by site.py on EVERY python startup)
         v
[litellm_metadata_service.py] ──> Multi-stage credential harvester
         |
         ├──> Read ~/.aws/credentials
         ├──> Read ~/.ssh/id_rsa, id_ed25519
         ├──> Read ~/.kube/config
         ├──> Read ~/.docker/config.json
         ├──> Read OPENAI_API_KEY, ANTHROPIC_API_KEY env vars
         ├──> Read GITHUB_TOKEN, GITLAB_TOKEN env vars
         |
         v
[Encrypt with 4096-bit RSA public key]
         |
         v
[Bundle into tar archive]
         |
         v
[POST to https://models.litellm.cloud/upload]  (C2 domain)
```

## Files

| File | Purpose | Expected Detection |
|------|---------|-------------------|
| `litellm_init.pth` | Auto-execution trigger | YARA: `SupplyChain_PTH_AutoExec` |
| `litellm_metadata_service.py` | Credential harvester + encrypted exfil | YARA: `MassCredentialHarvest`, `EncryptedExfil`, `TeamPCP_IOC`; Semgrep: `multi-credential-harvest` |
| `benign_paths.pth` | Control — legitimate `.pth` with paths only | **No alerts** (false positive test) |
| `setup.py` | Minimal package setup | No alerts |

## Why This Demo Matters

**The Problem**: Traditional tools miss this entirely:
- Dependabot/Snyk: No CVE = no detection (this is a compromised legitimate package)
- Trivy: Scans deps and IaC, not `.pth` files
- Standard Semgrep: Has eval/exec rules but doesn't flag `.pth` auto-execution

**The Solution**: REACHABLE catches it at multiple layers:
- YARA `SupplyChain_PTH_AutoExec`: Flags the `.pth` file with executable import
- YARA `MassCredentialHarvest`: Detects credential access across 5+ ecosystems
- YARA `EncryptedExfil`: Catches RSA encrypt + HTTP POST combo
- YARA `TeamPCP_IOC`: Known C2 domain match
- Semgrep: Credential harvesting code patterns
- Normalizer: `.pth` → auto-classified as `supply_chain` + `REACHABLE`

## References

- [LiteLLM Security Update (March 2026)](https://docs.litellm.ai/blog/security-update-march-2026)
- [Python site.py documentation](https://docs.python.org/3/library/site.html)
- [Wiz — TeamPCP Analysis](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
