# Framework Coverage Gaps — reach-testbed

> Date: 2026-03-26
> Owner: Al Dazzi, Sthenos Security
> Status: Living document — update as gaps are closed

## Purpose

The scanner (`reach-core`) has framework-specific detection plugins that classify
functions as REACHABLE, NOT_REACHABLE, or UNKNOWN based on framework routing patterns.
Each plugin needs testbed coverage to validate that:

1. Live routes are classified as REACHABLE
2. Dead code (not registered with the framework) is classified as NOT_REACHABLE
3. Ambiguous patterns (dynamic dispatch, reflection) are classified as UNKNOWN
4. Call graph edges connect entrypoints to sinks through framework routing

This document tracks which plugins have testbed coverage and which do not.

---

## Current Coverage

### Anchor frameworks (covered since v1.0)

| Language | Framework | Testbed Directories | Signal Matrix | Invocation Patterns | Call Graph Canary |
|----------|-----------|-------------------|:---:|:---:|:---:|
| Python | Flask | python-app/, signal-matrix/python/, invocation-patterns/python/ | ✅ | ✅ | — |
| JavaScript | Express | javascript-app/, signal-matrix/javascript/, npm-callgraph-test/, invocation-patterns/javascript/ | ✅ | ✅ | ✅ |
| TypeScript | Express | typescript-app/ | — | — | — |
| Go | Gin | go-app/, gin-app/, signal-matrix/go/, invocation-patterns/go/ | ✅ | ✅ | — |
| Java | Spring Boot | java-maven/, java-gradle/, java-callgraph-test/, signal-matrix/java/, invocation-patterns/java/ | ✅ | ✅ | ✅ |
| Kotlin | Spring Boot | kotlin-app/ | — | — | — |
| Groovy | Spring Boot | groovy-app/ | — | — | — |
| Ruby | Sinatra | ruby-app/ | — | — | — |
| Rust | Hyper | rust-app/ | — | — | — |
| Scala | Akka HTTP | scala-app/ | — | — | — |
| React | React | client-side-app/react/ | — | — | — |

### Framework test apps (added v1.6, expanded v1.7)

| App | Framework | Language | R | NR | U | Signals |
|-----|-----------|----------|--:|---:|--:|---------|
| django-app | Django + DRF | Python | 5 | 5 | 1 | CVE (pypdf, pyyaml), CWE-89, CWE-78, SECRET |
| fastapi-app | FastAPI | Python | 3 | 4 | 1 | CVE (pypdf, python-jose), CWE-22, CWE-78, SECRET |
| pyramid-app | Pyramid | Python | 2 | 3 | 0 | CVE (pypdf, pyyaml), CWE-78, SECRET |
| nestjs-app | NestJS | TypeScript | 3 | 3 | 0 | CVE (lodash, jwt), CWE-89, CWE-78, SECRET |
| fastify-app | Fastify | JavaScript | 3 | 3 | 1 | CVE (lodash, jwt), CWE-89, CWE-78, SECRET |
| hono-app | Hono | TypeScript | 2 | 3 | 1 | CVE (lodash, jwt), CWE-78, SECRET |
| echo-app | Echo | Go | 3 | 3 | 0 | CVE (x/text, yaml.v2), CWE-89, CWE-78, SECRET |
| gin-app | Gin | Go | 3 | 3 | 0 | CVE (x/text, yaml.v2), CWE-89, CWE-78, SECRET |

---

## Dead-Code Pattern Coverage (v1.7)

Each dead-code type validates a different scanner capability:

| Type | Meaning | What it tests |
|------|---------|---------------|
| **A** | Module/class imported but never registered/mounted | Scanner must trace framework registration (include_router, register_blueprint, app.use, @Module controllers, etc.) |
| **B** | Dead function in same file as live code | Scanner must trace call graph within imported modules — not just mark entire file reachable |
| **C** | Dead file/package never imported at all | Scanner must trace import graph from entrypoints — file is an island |

| App | Framework | A | B | C |
|-----|-----------|:-:|:-:|:-:|
| django-app | Django | ✅ dead_app not in INSTALLED_APPS | ✅ dead_inline_export in views.py | ✅ dead_views.py not in urlpatterns |
| fastapi-app | FastAPI | ✅ admin router imported, not include_router'd | ✅ dead_inline_exec in parse.py | ✅ dead/unused_router.py never imported |
| pyramid-app | Pyramid | ✅ @view_config with no matching route | ✅ dead_inline_parse in parse.py | ✅ dead/unused_views.py never imported |
| nestjs-app | NestJS | ✅ DeadController not in AppModule | ✅ deadInlineExec in user.controller.ts | ✅ dead/ directory never imported |
| fastify-app | Fastify | ✅ admin.js required, not register'd | ✅ deadInlineExec in merge.js | ✅ dead/dead-plugin.js never required |
| hono-app | Hono | ✅ admin.ts imported, not app.route'd | ✅ deadInlineExec in api.ts | ✅ dead/unused.ts never imported |
| echo-app | Echo | ✅ admin.go handlers never registered | ✅ DeadInlineExec in translate.go | ✅ dead/unused.go never imported |
| gin-app | Gin | ✅ admin.go handlers never registered | ✅ DeadInlineSearch in routes.go | ✅ dead/unused.go never imported |
| python-app | Flask | ✅ admin_bp imported, not registered | ✅ dead functions in app.py | ✅ dead/unused_views.py never imported |
| javascript-app | Express | ✅ admin_routes required, not app.use'd | ✅ dead functions in index.js | ✅ dead/unused_routes.js never required |
| go-app | Gin | ✅ admin_handlers.go never registered | ✅ unusedDatabaseConnection in main.go | ✅ dead/unused.go never imported |
| java-maven | Spring | ✅ AdminService @Service never injected | ✅ unusedMethod in Application.java | ✅ dead/DeadUtils.java no annotations |
| kotlin-app | Spring | ✅ AdminService @Service never injected | ✅ deadLog4jExec in Application.kt | ✅ dead/DeadUtils.kt no annotations |

---

## Gaps: Scanner Plugins With Zero Testbed Coverage

### Python — ✅ ALL CLOSED

| Framework | Scanner Plugin | Detection Patterns | Status | Test App |
|-----------|---------------|-------------------|--------|----------|
| **Django** | `plugins/django.py` | `urlpatterns`, `path()`, CBV `.as_view()` | ✅ Closed | `django-app/` |
| **Django REST Framework** | `plugins/django.py` | `ViewSet`, `@action`, `router.register()` | ✅ Closed | `django-app/` (integrated) |
| **FastAPI** | `plugins/fastapi.py` | `@router.post()`, `app.include_router()` | ✅ Closed | `fastapi-app/` |
| **Pyramid** | `plugins/pyramid.py` | `@view_config()`, `config.add_view()` | ✅ Closed | `pyramid-app/` |

### JavaScript / TypeScript — ✅ ALL CLOSED

| Framework | Scanner Plugin | Detection Patterns | Status | Test App |
|-----------|---------------|-------------------|--------|----------|
| **NestJS** | `plugins/nestjs.py` | `@Controller()`, `@Injectable()`, AppModule `controllers[]` | ✅ Closed | `nestjs-app/` |
| **Fastify** | `plugins/fastify.py` | `fastify.register()`, route handlers | ✅ Closed | `fastify-app/` |
| **Hono** | `plugins/hono.py` | `new Hono()`, `app.route()`, `export default app` | ✅ Closed | `hono-app/` |

### Go — ✅ ALL CLOSED

| Framework | Scanner Plugin | Detection Patterns | Status | Test App |
|-----------|---------------|-------------------|--------|----------|
| **Echo** | `plugins/echo.py` (EchoPlugin) | `echo.New()`, `e.GET()`, `e.Group()` | ✅ Closed | `echo-app/` |
| **Gin** | `plugins/echo.py` (GinPlugin) | `gin.Default()`, `r.GET()`, `r.Group()` | ✅ Closed | `gin-app/` |

Note: `net/http` (Go stdlib) has no scanner plugin — it falls back to generic FRI
heuristics. Adding a testbed app for it would help measure false negative rates.

---

## Remaining Gaps (not framework plugins)

| Item | Language | Category | Effort | Notes |
|------|----------|----------|--------|-------|
| `net/http` (Go stdlib) | Go | No plugin | 0.5d | Falls back to generic FRI heuristics. Testbed app would measure FN rate. |
| UNKNOWN signals | All | Coverage | 1d | Only django-app and hono-app have UNKNOWN test cases among framework apps. Others could benefit from UNKNOWN patterns. |
| DLP/AI/MALWARE in framework apps | All | Coverage | 1d | No framework-specific app has DLP, AI, or MALWARE signals. Only signal-matrix covers them. |
| `framework_validation` for Flask/Express/Spring | All | Assertions | 0.5d | These anchors have Type A/B/C dead-code assertions but no `framework_validation` canary entries (covered indirectly via reachability_validation). |

---

## How to Add a Test App

1. Create the directory under reach-testbed root (e.g., `django-app/`)
2. Write real route code with REACHABLE, NOT_REACHABLE, and UNKNOWN vulnerabilities
3. Include all three dead-code patterns:
   - **Type A**: Import the module but don't register/mount the routes
   - **Type B**: Add a dead function to an existing live file
   - **Type C**: Create a `dead/` directory with files never imported
4. Add validation entries to `testbed.json` in `framework_validation`:
   ```json
   {
     "description": "[FRAMEWORK] CVE in live route — must be REACHABLE",
     "framework": "framework-name",
     "file": "app-dir/path/to/file.py",
     "function": "handler_name",
     "expected_reachability": "REACHABLE",
     "canary": true,
     "dead_code_type": null,
     "note": "Description of how the route is wired"
   }
   ```
5. Run: `reachctl scan reach-testbed/app-dir && python validate.py --db ~/.reachable/scans/app-dir/repo.db`
6. Update `SIGNAL-INVENTORY.md` with new signals
7. Update this document to mark the gap as closed

---

## Revision History

| Date | Change |
|------|--------|
| 2026-03-26 | Initial gap analysis — 7 scanner plugins with zero testbed coverage identified |
| 2026-03-26 | All 7 gaps closed: django-app, fastapi-app, pyramid-app, nestjs-app, fastify-app, hono-app, echo-app created. 22 framework_validation assertions added to testbed.json v1.6. SIGNAL-INVENTORY.md updated (112 → 134 assertions). |
| 2026-03-26 | v1.7: gin-app created. Dead-code Type A/B/C coverage added to all 13 framework apps. 26 new dead-code pattern assertions in testbed.json. SIGNAL-INVENTORY.md updated (134 → 160 assertions). |
