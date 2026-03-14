# Invocation Patterns Test Suite

Tests the three fundamental ways code can execute, across all languages.
Used to validate both the deterministic call graph (RA) and the AI reachability analyzer (enzo analyze).

## The Three Cases

| Case | Pattern | Expected State | Who Detects |
|------|---------|---------------|-------------|
| **1. External endpoint** | HTTP route → function → sink | REACHABLE | Call graph ✅ + AI taint ✅ |
| **2. Internal trigger** | thread/timer/init/startup → function → sink | REACHABLE (internal) | Call graph ❌ (gap) + AI behavioral ⚠️ |
| **3. Dead code** | function exists, never called | NOT_REACHABLE | Call graph ✅ |

## Case 2 Subtypes (Internal Triggers)

| Subtype | Python | JavaScript | Go | Java |
|---------|--------|------------|-----|------|
| Threading | `threading.Thread/Timer.start()` | `new Worker()` | `go func(){}()` | `new Thread().start()` |
| Timer/scheduled | `sched.scheduler` | `setInterval/setTimeout` | `time.AfterFunc` | `@Scheduled`, `ScheduledExecutorService` |
| Startup/init | `atexit.register()`, `@app.before_first_request` | `process.on('exit')`, IIFE | `func init()` | `@PostConstruct`, `static {}` |
| Module-level | top-level calls | top-level calls | `init()` | static initializer blocks |
| Signal handler | `signal.signal()` | `process.on('SIGINT')` | `signal.Notify` | `Runtime.addShutdownHook` |

## Risk Matrix (from ChatGPT analysis)

| Reachable | Tainted | Behavior | Classification |
|-----------|---------|----------|---------------|
| yes (external) | yes | shell exec | **Command Injection** (CRITICAL) |
| yes (external) | no | dangerous exec | **Unsafe API** (HIGH) |
| yes (internal) | no | C2 download | **Malware** (CRITICAL) |
| yes (internal) | no | normal API call | **Benign internal** (LOW) |
| no | no | any | **Dead code** (INFO) |

## Test Matrix

| File | Lang | Case | CWE | Expected Reach | Expected Taint |
|------|------|------|-----|---------------|----------------|
| `python/http_endpoint.py` | Python | 1 | CWE-89, CWE-78 | REACHABLE | ATTACKER_CONTROLLED |
| `python/internal_trigger.py` | Python | 2 | CWE-78, CWE-200 | REACHABLE (internal) | SAFE (constant) |
| `python/dead_code.py` | Python | 3 | CWE-89, CWE-78 | NOT_REACHABLE | N/A |
| `javascript/http_endpoint.js` | JS | 1 | CWE-89, CWE-78 | REACHABLE | ATTACKER_CONTROLLED |
| `javascript/internal_trigger.js` | JS | 2 | CWE-78, CWE-918 | REACHABLE (internal) | SAFE (constant) |
| `javascript/dead_code.js` | JS | 3 | CWE-89, CWE-78 | NOT_REACHABLE | N/A |
| `go/main.go` | Go | 1+2+3 | CWE-89, CWE-78 | mixed | mixed |
| `java/InvocationPatterns.java` | Java | 1+2+3 | CWE-89, CWE-78 | mixed | mixed |

## Running

```bash
# Scan
reachctl scan /path/to/reach-testbed

# AI analyze
reachctl enzo analyze /path/to/reach-testbed --type cwe --mode cloud --provider groq

# Validate
sqlite3 ~/.reachable/scans/reach-testbed-*/repo.db "
  SELECT file_path, line_number, app_reachability, taint_verdict
  FROM findings WHERE file_path LIKE '%invocation-patterns%'
  ORDER BY file_path, line_number
"
```
