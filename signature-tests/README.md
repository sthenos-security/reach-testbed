# Signature-Based Detection Tests

> Test REACHABLE's ability to detect AND filter malware signatures by reachability.

## Overview

This directory contains safe, non-malicious test signatures for validating REACHABLE's detection pipeline. These are industry-standard testing artifacts that trigger detection without causing harm.

## Test Signatures

### 1. EICAR Test String (Industry Standard)

The canonical antivirus test signature. Harmless but triggers signature-based scanners.

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

**Known Hashes:**
| Algorithm | Hash |
|-----------|------|
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14140` |
| SHA256 | `275a021bbfb6489e54d471899f7db9d2c3c2a5c4f3f84dca0a38b0c3e5b0a6a3` |

### 2. Custom Synthetic Signatures

Deterministic markers for pipeline validation:

```
TEST-MALWARE-SIGNATURE-12345
FAKE_RANSOMWARE_MARKER::ENCRYPT_START
CMD_EXEC_SIMULATION && rm -rf /fake/path
REACHABLE_TEST_BEACON::C2_CALLBACK
CRYPTO_MINER_POOL::stratum+tcp://test.pool
```

### 3. Synthetic Bad Hashes

For hash-based detection testing:

```
SHA256: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
SHA256: cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe
```

## Test Structure

```
signature-tests/
├── samples/
│   ├── reachable/           # Signatures in REACHABLE code paths
│   │   ├── active_loader.js
│   │   └── live_beacon.py
│   └── unreachable/         # Signatures in DEAD code paths
│       ├── dead_code.js
│       └── unused_module.py
├── yara-rules/
│   ├── test_signatures.yar  # YARA rules for all test signatures
│   └── eicar.yar            # EICAR-specific rule
└── expected/
    └── reachability-demo.json
```

## The Demo Point

**Traditional Scanner Output:**
```
⚠️ MALWARE DETECTED: 4 signatures found
  - active_loader.js: EICAR test signature
  - live_beacon.py: C2 beacon pattern
  - dead_code.js: EICAR test signature
  - unused_module.py: Ransomware marker
```

**REACHABLE Output:**
```
🔴 CRITICAL: 2 reachable malware signatures
  - active_loader.js: EICAR (REACHABLE from index.js)
  - live_beacon.py: C2 beacon (REACHABLE from main.py)

⚪ INFO: 2 unreachable signatures (deprioritized)
  - dead_code.js: EICAR (UNREACHABLE - no call path)
  - unused_module.py: Ransomware marker (UNREACHABLE - never imported)

Noise Reduction: 50% (4 → 2 actionable)
```

## Running Tests

```bash
# Scan with YARA rules
yara -r yara-rules/test_signatures.yar samples/

# Run REACHABLE for reachability analysis
reachctl scan . --include-malware --output results.json

# Compare results
./run-signature-test.sh
```
