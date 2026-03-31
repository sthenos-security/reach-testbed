# Signature-Based Detection Tests

> Validates REACHABLE's ability to **detect** malware signatures AND **filter by reachability** — surfacing only what can actually execute.

---

## Overview

Two test objectives in one directory:

**1. Reachability filtering demo** (`samples/`) — shows that REACHABLE reduces false-positive noise by 50%+ by filtering signatures through the call graph. Traditional scanners flag every match; REACHABLE only surfaces matches in live code paths.

**2. Obfuscation detection rules** (`yara-rules/`) — YARA and Semgrep rules covering all URL obfuscation techniques observed in real supply chain attacks (2022–2026).

---

## Test Structure

```
signature-tests/
├── samples/                        # Reachability filtering demo app
│   ├── index.js                    # Entry point — imports reachable/ only
│   ├── package.json
│   ├── reachable/
│   │   ├── active_loader.js        # REACHABLE — EICAR + obfuscation
│   │   └── live_beacon.js          # REACHABLE — C2 beacon + exfil markers
│   └── unreachable/
│       ├── dead_code.js            # NOT_REACHABLE — EICAR (never imported)
│       └── unused_module.js        # NOT_REACHABLE — ransomware + miner (never imported)
├── yara-rules/
│   ├── test_signatures.yar         # EICAR + synthetic test markers
│   ├── supply_chain_url_obfuscation.yar   # T1–T8 runtime URL obfuscation (15 rules)
│   └── supply_chain_obfuscation.yml       # Semgrep rules (32 rules, validated)
└── expected/
    └── reachability-demo.json      # Ground-truth: 10 findings → 5 actionable (50% noise reduction)
```

---

## Reachability Filtering Demo

### What `index.js` imports

```js
// REACHABLE — these ARE imported and called from main()
const activeLoader = require('./reachable/active_loader');
const liveBeacon   = require('./reachable/live_beacon');

// NOT_REACHABLE — commented out, never imported
// const deadCode     = require('./unreachable/dead_code');
// const unusedModule = require('./unreachable/unused_module');
```

### Traditional scanner output (10 findings, all CRITICAL)

```
⚠️  reachable/active_loader.js   EICAR_Test_Signature      CRITICAL
⚠️  reachable/active_loader.js   Test_Malware_Marker       CRITICAL
⚠️  reachable/active_loader.js   Test_Obfuscation_Pattern  CRITICAL
⚠️  reachable/live_beacon.js     Test_C2_Beacon            CRITICAL
⚠️  reachable/live_beacon.js     Test_Data_Exfiltration    CRITICAL
⚠️  unreachable/dead_code.js     EICAR_Test_Signature      CRITICAL  ← noise
⚠️  unreachable/dead_code.js     Test_Malware_Marker       CRITICAL  ← noise
⚠️  unreachable/unused_module.js Test_Ransomware_Pattern   CRITICAL  ← noise
⚠️  unreachable/unused_module.js Test_C2_Beacon            CRITICAL  ← noise
⚠️  unreachable/unused_module.js Test_Crypto_Miner         CRITICAL  ← noise
```

### REACHABLE output (5 actionable, 5 deprioritised)

```
🔴 CRITICAL  reachable/active_loader.js   init()        EICAR_Test_Signature      [main→activeLoader.init()]
🔴 CRITICAL  reachable/active_loader.js   init()        Test_Malware_Marker       [main→activeLoader.init()]
🔴 CRITICAL  reachable/active_loader.js   decode()      Test_Obfuscation_Pattern  [module scope]
🔴 CRITICAL  reachable/live_beacon.js     checkin()     Test_C2_Beacon            [main→liveBeacon.checkin()]
🔴 CRITICAL  reachable/live_beacon.js     exfiltrate()  Test_Data_Exfiltration    [module scope]

⬜ NOT_REACHABLE  unreachable/dead_code.js     neverCalled()     EICAR              — module never imported
⬜ NOT_REACHABLE  unreachable/dead_code.js     alsoNeverCalled() Test_Malware_Marker— module never imported
⬜ NOT_REACHABLE  unreachable/unused_module.js encryptFiles()    Ransomware         — module never imported
⬜ NOT_REACHABLE  unreachable/unused_module.js callHome()        C2_Beacon          — module never imported
⬜ NOT_REACHABLE  unreachable/unused_module.js mineCoins()       Crypto_Miner       — module never imported

Noise reduction: 50% (10 → 5 actionable)
```

---

## URL Obfuscation Rules (`yara-rules/`)

### `supply_chain_url_obfuscation.yar` — 15 YARA rules

Covers runtime URL obfuscation techniques extracted from real supply chain attacks:

| Rule | Technique | Real-World Reference |
|------|-----------|---------------------|
| `SupplyChain_B64_URL_Decode_Network` | base64-encoded C2 URL | LiteLLM/TeamPCP March 2026 |
| `SupplyChain_TeamPCP_IOC_B64` | Known IOC base64 literal | `models.litellm.cloud`, `checkmarx.zone` |
| `SupplyChain_XOR_URL_Decode_Network` | XOR-encoded C2 URL | plain-crypto-js `OrDeR_7077` key |
| `SupplyChain_IE8_UserAgent` | IE8 UA C2 fingerprint | plain-crypto-js@4.2.1 |
| `SupplyChain_CharCode_Array_URL` | `chr()`/`fromCharCode` URL | npm campaigns 2022-2025 |
| `SupplyChain_AES_Hardcoded_Key_Network` | AES-CTR encrypted URL | Advanced PyPI infostealers |
| `SupplyChain_MultiLayer_ZlibB64_Network` | zlib+base64 two-layer | Muad'Dib simulation |
| `SupplyChain_DNS_Subdomain_Exfil` | DNS covert channel | Muad'Dib Stage 5, shai-hulud Stage 6 |
| `SupplyChain_LegitDomain_Exfil_GithubGist` | GitHub Gist as dead drop | npm/PyPI 2023-2024 |
| `SupplyChain_LegitDomain_Exfil_Discord` | Discord webhook exfil | npm/PyPI 2022-2025 |
| `SupplyChain_LegitDomain_Exfil_Telegram` | Telegram bot exfil | PyPI campaigns 2023-2025 |
| `SupplyChain_LegitDomain_Exfil_S3` | S3 PUT exfil | Advanced attacks 2024-2025 |
| `SupplyChain_MassCredentialHarvest` | 5+ credential paths | LiteLLM/TeamPCP, ctx, ultrarequests |
| `SupplyChain_EnvVar_Mass_Harvest` | 5+ high-value env vars | ctx, dozens of PyPI attacks |
| `SupplyChain_EncryptedExfil` | RSA encrypt then POST | LiteLLM v1.82.7/1.82.8 |
| `SupplyChain_URL_Obfuscation_Any` | Meta rule (any of above) | — |

### `supply_chain_obfuscation.yml` — 32 Semgrep rules (validated)

Python-specific Semgrep rules for the same techniques. All rules validated against target files with 0 errors.

| Technique | Rules | Validated Against |
|-----------|-------|-------------------|
| T1 base64 URL | `python-malware-b64decode-url-assign-urlopen`, `python-malware-teamPCP-ioc-primary-str`, `python-malware-double-b64decode` | `fake-litellm-b64-c2` |
| T2 XOR URL | `python-malware-xor-decode-with-args`, `python-malware-xor-function-return` | `fake-xor-c2` |
| T3 chr() sequence | `python-malware-chr-https-prefix` | `fake-chr-sequence-c2` |
| T4 AES decrypt | `python-malware-aes-ctr-import`, `python-malware-crypto-cipher-aes-urlopen` | `fake-aes-decrypt-c2` |
| T5 zlib+b64 | `python-malware-zlib-decompress-b64decode` | `fake-zlib-b64-c2` |
| T6 DNS exfil | `python-malware-dns-exfil-getaddrinfo-loop`, `python-malware-b32encode-in-file-with-getaddrinfo` | `fake-dns-subdomain-exfil` |
| T7 legit-domain C2 | `python-malware-github-gist-literal-call`, `python-malware-telegram-metavar`, `python-malware-discord-webhook-metavar` | `fake-legit-domain-c2` |
| T8 mass harvest | `python-malware-credential-dict-aws-ssh`, `python-malware-env-loop-aws-github`, `python-malware-env-loop-llm-keys` | `fake-litellm-b64-c2` |
| Install hook | `python-malware-cmdclass-install-calls-exfil`, `python-malware-setuptools-cmdclass-network-file` | `fake-litellm-b64-c2`, `fake-xor-c2` |

---

## Key Design Principle

**Source obfuscation is irrelevant to dynamic detection.** Every technique above — base64, XOR, AES, chr() sequences, zlib, eval chains — requires the plaintext hostname to exist in memory before `socket.connect()` fires. Our sandbox intercepts at the socket layer, after all decoding is complete.

Static rules (YARA/Semgrep) detect the **encoding mechanism + network action pair**, not the destination domain. This is why domain reputation lists are a secondary signal, not the primary gate.

---

## Running Tests

```bash
yara -r yara-rules/supply_chain_url_obfuscation.yar \
     ../static-malware-tests/ \
     ../malware-test-packages/

semgrep --config yara-rules/supply_chain_obfuscation.yml \
        ../static-malware-tests/

yara -r yara-rules/test_signatures.yar samples/
```
