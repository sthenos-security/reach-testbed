# Invocation Patterns Test Suite

Tests the three fundamental ways code can execute, across all languages.
Used to validate both the deterministic call graph (RA) and the AI reachability analyzer (enzo analyze).

## The Four Cases

| Case | Pattern | Expected State | Who Detects |
|------|---------|---------------|-------------|
| **1. External endpoint** | HTTP route → function → sink | REACHABLE | Call graph ✅ + AI taint ✅ |
| **2. Internal trigger** | thread/timer/init/startup → function → sink | REACHABLE (internal) | Call graph ❌ (gap) + AI behavioral ⚠️ |
| **3. Dead code** | function exists, never called | NOT_REACHABLE | Call graph ✅ |
| **4. Dynamic invocation** | reflection/eval/dispatch table/fn variable → sink | REACHABLE / UNKNOWN | Call graph ⚠️ (PARTIAL or NO) + AI ⚠️ |

## Case 4 Subtypes (Dynamic Invocation)

| Subtype | Python | JavaScript | Go | Java | CG coverage |
|---------|--------|------------|-----|------|-------------|
| Dict/map dispatch | `DISPATCH_TABLE[key](data)` | `handlers[action](data)` | `dispatchMap[key](val)` | `Map<String,Function>` | PARTIAL |
| Function variable | `fn = myfunc; fn()` | `const fn = myFn; fn()` | `fn := myFunc; go fn()` | `Function<T,R> fn = this::method` | YES (after fix) |
| Async callback | `map(fn, items)` | `setTimeout(fn, 0)`, `.then(fn)` | goroutine fn value | `executor.submit(() -> fn())` | YES (after fix) |
| eval / exec | `eval(user_expr)` | `eval(expr)` | N/A | N/A | PARTIAL |
| Reflection | `getattr(mod, name)()` | `obj[key]()` (computed) | `reflect.Value.Call()` | `Method.invoke()` | NO |
| Dynamic import | `importlib.import_module(name)` | `require(variable)` | `plugin.Open(path)` | `Class.forName(name)` | NO |

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
| `python/dynamic_invocation.py` | Python | 4 | CWE-78, CWE-89, CWE-94, CWE-22 | mixed | mixed |
| `javascript/http_endpoint.js` | JS | 1 | CWE-89, CWE-78 | REACHABLE | ATTACKER_CONTROLLED |
| `javascript/internal_trigger.js` | JS | 2 | CWE-78, CWE-918 | REACHABLE (internal) | SAFE (constant) |
| `javascript/dead_code.js` | JS | 3 | CWE-89, CWE-78 | NOT_REACHABLE | N/A |
| `javascript/dynamic_invocation.js` | JS | 4 | CWE-89, CWE-78, CWE-95, CWE-22, CWE-829 | mixed | mixed |
| `go/main.go` | Go | 1+2+3 | CWE-89, CWE-78 | mixed | mixed |
| `go/dynamic_invocation.go` | Go | 4 | CWE-89, CWE-78, CWE-22, CWE-829 | mixed | mixed |
| `java/InvocationPatterns.java` | Java | 1+2+3 | CWE-89, CWE-78 | mixed | mixed |
| `java/DynamicInvocation.java` | Java | 4 | CWE-89, CWE-78, CWE-22, CWE-829 | mixed | mixed |

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
