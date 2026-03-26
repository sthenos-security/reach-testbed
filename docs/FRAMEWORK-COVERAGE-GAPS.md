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

One framework per language is covered. These are the "anchor" frameworks.

| Language | Framework | Testbed Directories | Signal Matrix | Invocation Patterns | Call Graph Canary |
|----------|-----------|-------------------|:---:|:---:|:---:|
| Python | Flask | python-app/, signal-matrix/python/, invocation-patterns/python/ | ✅ | ✅ | — |
| JavaScript | Express | javascript-app/, signal-matrix/javascript/, npm-callgraph-test/, invocation-patterns/javascript/ | ✅ | ✅ | ✅ |
| TypeScript | Express | typescript-app/ | — | — | — |
| Go | Gin | go-app/, signal-matrix/go/, invocation-patterns/go/ | ✅ | ✅ | — |
| Java | Spring Boot | java-maven/, java-gradle/, java-callgraph-test/, signal-matrix/java/, invocation-patterns/java/ | ✅ | ✅ | ✅ |
| Kotlin | Spring Boot | kotlin-app/ | — | — | — |
| Groovy | Spring Boot | groovy-app/ | — | — | — |
| Ruby | Sinatra | ruby-app/ | — | — | — |
| Rust | Hyper | rust-app/ | — | — | — |
| Scala | Akka HTTP | scala-app/ | — | — | — |
| React | React | client-side-app/react/ | — | — | — |

---

## Gaps: Scanner Plugins With Zero Testbed Coverage

These frameworks have full detection plugins in `reach-core/reachable/analysis/plugins/`
but no test app in reach-testbed.

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

Note: `net/http` (Go stdlib) has no scanner plugin — it falls back to generic FRI
heuristics. Adding a testbed app for it would help measure false negative rates.

---

## Proposed Test Apps

Each new test app should follow the same pattern as the existing anchor frameworks:

1. **Real route code** — actual HTTP handlers with request/response
2. **Reachable CVE** — at least one vulnerable dependency called from a live route
3. **Not-reachable CVE** — at least one vulnerable dependency imported but never called from any route
4. **Reachable CWE** — at least one SAST finding (SQL injection, command injection, etc.) in a live route
5. **Reachable secret** — at least one hardcoded credential in a live route
6. **Dead code** — at least one handler/controller/view that is NOT registered with the framework router
7. **testbed.json entries** — validation assertions for each expected reachability state

### django-app/ (P0)

```
django-app/
├── manage.py
├── requirements.txt           # django==4.2, djangorestframework, pypdf==3.1.0, pyyaml==5.4
├── myproject/
│   ├── settings.py
│   ├── urls.py                # urlpatterns with path() includes
│   └── wsgi.py
├── api/
│   ├── urls.py                # path('parse/', views.parse_pdf)
│   ├── views.py               # FBV: parse_pdf() → pypdf (CVE REACHABLE)
│   ├── viewsets.py            # DRF ViewSet: UserViewSet with @action
│   ├── serializers.py
│   └── dead_views.py          # Views NOT in any urlpatterns (NOT_REACHABLE)
└── dead_app/
    └── views.py               # Entire app not in INSTALLED_APPS (NOT_REACHABLE)
```

**What it validates:**
- `urlpatterns` → `path()` route detection
- DRF `router.register()` → ViewSet method detection
- `@api_view(['POST'])` decorator detection
- Class-based views with `.as_view()` in urlpatterns
- Dead views not in any urlpatterns → NOT_REACHABLE
- Dead app not in INSTALLED_APPS → NOT_REACHABLE

### fastapi-app/ (P1)

```
fastapi-app/
├── requirements.txt           # fastapi, uvicorn, pypdf==3.1.0, python-jose==3.3.0
├── main.py                    # app = FastAPI(); app.include_router(api_router)
├── routers/
│   ├── parse.py               # @router.post("/parse") → pypdf (CVE REACHABLE)
│   └── auth.py                # @router.post("/login") → python-jose (CVE REACHABLE)
├── services/
│   └── dead_service.py        # Functions never imported by any router (NOT_REACHABLE)
└── deprecated/
    └── old_api.py             # Router defined but never included (NOT_REACHABLE)
```

**What it validates:**
- `@app.get()` / `@router.post()` route detection
- `app.include_router()` registration
- Sub-router mounting
- Dead routers (defined but never included) → NOT_REACHABLE

### nestjs-app/ (P0)

```
nestjs-app/
├── package.json               # @nestjs/core, @nestjs/common, lodash@4.17.20, class-validator
├── tsconfig.json
├── src/
│   ├── main.ts                # NestFactory.create(AppModule)
│   ├── app.module.ts          # @Module({ controllers: [UserController], providers: [UserService] })
│   ├── user/
│   │   ├── user.controller.ts # @Controller('users'), @Get(), @Post() → lodash (CVE REACHABLE)
│   │   └── user.service.ts    # @Injectable() → SQL query (CWE REACHABLE)
│   └── dead/
│       ├── dead.controller.ts # @Controller('dead') — NOT in AppModule controllers[] (NOT_REACHABLE)
│       └── dead.service.ts    # @Injectable() — NOT in AppModule providers[] (NOT_REACHABLE)
```

**What it validates:**
- `@Controller()` + `@Get()`/`@Post()` route detection
- `AppModule` `controllers[]` array registration
- `@Injectable()` provider detection
- Dead controllers not in AppModule → NOT_REACHABLE

### fastify-app/ (P1)

```
fastify-app/
├── package.json               # fastify, @fastify/cors, lodash@4.17.20
├── server.js                  # fastify.register(routes); fastify.listen()
├── routes/
│   ├── merge.js               # fastify.post('/merge', handler) → lodash (CVE REACHABLE)
│   └── health.js              # fastify.get('/health', handler)
└── plugins/
    └── dead-plugin.js         # Plugin defined but never registered (NOT_REACHABLE)
```

**What it validates:**
- `fastify.get()`/`fastify.post()` route detection
- `fastify.register()` plugin registration
- Dead plugins (never registered) → NOT_REACHABLE

### echo-app/ (P1)

```
echo-app/
├── go.mod                     # github.com/labstack/echo/v4, golang.org/x/text@v0.3.7
├── main.go                    # e := echo.New(); e.GET("/translate", handlers.Translate)
├── handlers/
│   ├── translate.go           # func Translate(c echo.Context) → x/text (CVE REACHABLE)
│   └── health.go              # func Health(c echo.Context) → safe
└── dead/
    └── unused.go              # func DeadHandler(c echo.Context) — never registered (NOT_REACHABLE)
```

**What it validates:**
- `echo.New()` + `e.GET()`/`e.POST()` route detection
- `e.Group()` route grouping
- Dead handlers (never registered with router) → NOT_REACHABLE
- Distinguishes Echo from Gin (currently both in echo.py)

### hono-app/ (P2)

```
hono-app/
├── package.json               # hono, @hono/node-server
├── src/
│   ├── index.ts               # const app = new Hono(); export default app
│   ├── routes/
│   │   └── api.ts             # app.get('/api/data', handler) → vulnerable dep
│   └── dead/
│       └── unused.ts          # Route handler never mounted
└── wrangler.toml              # Cloudflare Workers config (optional)
```

---

## Expansion Priorities

### Phase 1 — P0 (block b37 release)

| App | Language | Framework | Effort | Depends On |
|-----|----------|-----------|--------|------------|
| django-app | Python | Django + DRF | 1.5d | django.py plugin validation |
| nestjs-app | TypeScript | NestJS | 1d | nestjs.py plugin validation |

These are the two most popular frameworks in their ecosystems that we claim to support.
Shipping without testbed validation is a regression risk.

### Phase 2 — P1 (b37 or b38)

| App | Language | Framework | Effort | Depends On |
|-----|----------|-----------|--------|------------|
| fastapi-app | Python | FastAPI | 1d | fastapi.py plugin validation |
| fastify-app | JavaScript | Fastify | 0.5d | fastify.py plugin validation |
| echo-app | Go | Echo | 0.5d | echo.py EchoPlugin validation |

### Phase 3 — P2/P3 (backlog)

| App | Language | Framework | Effort | Notes |
|-----|----------|-----------|--------|-------|
| hono-app | TypeScript | Hono | 0.5d | Serverless/edge niche |
| pyramid-app | Python | Pyramid | 0.5d | Low market share |
| nethttp-app | Go | net/http (stdlib) | 0.5d | No plugin exists yet — would test FRI fallback accuracy |

---

## How to Add a Test App

1. Create the directory under reach-testbed root (e.g., `django-app/`)
2. Write real route code with at least one REACHABLE and one NOT_REACHABLE vulnerability
3. Add validation entries to `testbed.json`:
   ```json
   {
     "repo": "django-app",
     "assertions": [
       {"finding_id": "CVE-2022-XXXX", "expected_state": "REACHABLE", "reason": "called from urlpatterns path()"},
       {"finding_id": "CVE-2022-YYYY", "expected_state": "NOT_REACHABLE", "reason": "dead_views.py not in any urlpatterns"}
     ]
   }
   ```
4. Run: `reachctl scan reach-testbed/django-app && python validate.py --db ~/.reachable/scans/django-app/repo.db`
5. Update `SIGNAL-INVENTORY.md` with new signals
6. Update this document to mark the gap as closed

---

## Revision History

| Date | Change |
|------|--------|
| 2026-03-26 | Initial gap analysis — 7 scanner plugins with zero testbed coverage identified |
| 2026-03-26 | All 7 gaps closed: django-app, fastapi-app, pyramid-app, nestjs-app, fastify-app, hono-app, echo-app created. 22 framework_validation assertions added to testbed.json v1.6. SIGNAL-INVENTORY.md updated (112 → 134 assertions). |
| 2026-03-26 | v1.7: gin-app created. Dead-code Type A/B/C coverage added to all 13 framework apps. 26 new dead-code pattern assertions in testbed.json. SIGNAL-INVENTORY.md updated (134 → 160 assertions). |
