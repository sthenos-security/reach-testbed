# 🐛 Shai-Hulud Simulation

> **⚠️ SECURITY TEST PACKAGE** - This is a safe simulation of the Shai-Hulud supply chain attack for demonstrating REACHABLE's detection capabilities.

## Overview

This package simulates the **Shai-Hulud** npm supply chain attack, a sophisticated credential-stealing malware that targeted developer npm tokens, SSH keys, and AWS credentials through malicious postinstall hooks.

## Why This Demo Matters

**The Problem**: Traditional security tools see fragments:
- Semgrep finds "hardcoded URLs" (no context)
- GuardDog finds "postinstall hook" (high false positive rate)
- Trivy/Grype find **nothing** (no CVEs = no detection)

**The Solution**: REACHABLE correlates all signals:
- Entry point analysis → postinstall WILL execute
- Call graph → all malicious paths are REACHABLE
- Multi-signal correlation → 7 findings → 1 critical verdict
- **Result: BLOCK INSTALLATION**

## Quick Demo

```bash
# Run comparison (shows expected results)
./run-comparison.sh

# Run with actual tools (requires semgrep, guarddog, trivy, grype, reachctl)
./run-comparison.sh --full
```

## Attack Chain

```
npm install
     │
     ▼
[postinstall] ──► loader.js ──► harvester.js ──► Steal credentials
                      │                              │
                      └──────► exfil.js ◄────────────┘
                                   │
                                   ▼
                            Attacker C2 server
```

## Files

| File | Purpose |
|------|---------|
| `package.json` | Entry point (postinstall hook) |
| `lib/loader.js` | Stage 1: Obfuscated loader |
| `lib/harvester.js` | Stage 2: Credential theft |
| `lib/exfil.js` | Stage 3: Data exfiltration |
| `docs/ATTACK-CHAIN.md` | Detailed attack flow |
| `docs/COMPARISON-MATRIX.md` | Tool comparison |
| `expected/*.json` | Expected results from each tool |
| `run-comparison.sh` | Demo comparison script |

## Detection Signals

REACHABLE correlates these 7 signals into 1 critical finding:

1. **GuardDog**: postinstall execution hook
2. **GuardDog**: obfuscated/encoded code patterns  
3. **GuardDog**: delayed execution (setTimeout)
4. **Semgrep**: CWE-94 (code injection via dynamic require)
5. **Semgrep**: CWE-22 (path traversal to sensitive files)
6. **Semgrep**: CWE-798 (hardcoded C2 endpoints)
7. **CallGraph**: All malicious paths REACHABLE from entry

## Safety

This simulation is **safe for testing**:
- Uses `.test` TLD domains (RFC 2606 - guaranteed not to resolve)
- Credentials are masked, not actually stolen
- Marked `"private": true` - cannot be published to npm
- All network requests will fail silently

## References

- [Phylum Blog: Shai-Hulud Attack Analysis](https://blog.phylum.io)
- [Socket.dev: npm Install Script Issues](https://socket.dev)
- [Dune (Frank Herbert)](https://en.wikipedia.org/wiki/Dune_(novel)) - The sandworm namesake
