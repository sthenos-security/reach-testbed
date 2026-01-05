# REACHABLE Test Bed

Comprehensive test repository demonstrating all REACHABLE features.

## Purpose

1. **Validation** - Prove REACHABLE detects what it claims
2. **Regression** - Ensure releases don't break functionality
3. **Demo** - Show customers real scan output
4. **Documentation** - Examples of all vulnerability types

## Test Cases

| Directory | Language | Features Tested |
|-----------|----------|-----------------|
| `python-app/` | Python | CVEs, secrets, reachability, malware patterns |
| `javascript-app/` | JS/TS | npm vulns, call graph, entrypoints |
| `go-app/` | Go | go.mod vulns, FFI detection |
| `java-maven/` | Java | Maven multi-module, Spring entrypoints |
| `java-gradle/` | Java/Kotlin | Gradle Kotlin DSL, Android |
| `kotlin-app/` | Kotlin | Coroutines, Android lifecycle |
| `polyglot-monorepo/` | Mixed | Cross-language, microservices |

## Expected Results

Each test case has a corresponding `expected-results/*.json` file with:
- Expected CVE count (reachable vs total)
- Expected secrets count
- Expected entrypoints
- Expected risk level

## Validation Workflow

```bash
# Run REACHABLE on test case
reachctl scan python-app/ --json > actual.json

# Compare with expected
python validate.py actual.json expected-results/python-app.json
```

## CI/CD Integration

The `.github/workflows/validate.yml` workflow:
1. Runs REACHABLE on each test case
2. Compares output to expected results
3. Fails if detection rates drop

## Test Case Details

### python-app/
- **CVE-2021-44228** - Log4Shell (transitive via py4j) - UNREACHABLE
- **CVE-2022-42969** - py-pdf ReDoS - REACHABLE
- **Hardcoded AWS key** - In reachable code path
- **Dead secret** - Revoked key in unreachable function

### javascript-app/
- **CVE-2021-23337** - lodash prototype pollution - REACHABLE
- **CVE-2020-28469** - glob-parent ReDoS - UNREACHABLE
- **npm malware pattern** - base64 decode + eval

### java-maven/
- **CVE-2022-22965** - Spring4Shell - REACHABLE via @PostMapping
- **CVE-2021-42392** - H2 Console RCE - UNREACHABLE (test scope)
- Multi-module with parent POM inheritance

### go-app/
- **CVE-2022-32149** - golang.org/x/text DoS - REACHABLE
- **CGO boundary** - Unsafe C call detection

## Running Tests

```bash
# Install REACHABLE
pip install reachable

# Run all validations
./run-tests.sh

# Run single test
reachctl scan python-app/ --output results/python/
```

## Adding New Test Cases

1. Create directory with vulnerable code
2. Document expected CVEs in README
3. Add `expected-results/{name}.json`
4. Update validation workflow

## License

MIT - For testing purposes only.
