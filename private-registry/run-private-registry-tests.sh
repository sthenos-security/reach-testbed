#!/usr/bin/env bash
# Copyright © 2026 Sthenos Security. All rights reserved.
# run-private-registry-tests.sh
#
# End-to-end: start registries → populate → install deps → run tests
#
# Auth model per registry:
#   devpi:      pip.conf extra-index-url (user/pass handled by devpi login in setup.sh)
#   Verdaccio:  .npmrc scoped registry + publish:$all / access:$all (no token needed for read)
#   Athens:     GOPROXY env var (no auth — public proxy cache)
#   Reposilite: settings.xml <server> admin:secret (only needed for deploy, not resolve)
#
# Usage:
#   cd reach-testbed/private-registry
#   ./run-private-registry-tests.sh          # full run
#   ./run-private-registry-tests.sh --skip-setup   # reuse running containers

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SKIP_SETUP=false
[[ "${1:-}" == "--skip-setup" ]] && SKIP_SETUP=true

log()  { echo -e "${CYAN}[registry-test]${NC} $*"; }
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }

DEVPI_URL="http://localhost:3141"
VERDACCIO_URL="http://localhost:4873"
ATHENS_URL="http://localhost:3000"
REPOSILITE_URL="http://localhost:8081"

TARGET="$SCRIPT_DIR/target-projects"

# ═══════════════════════════════════════════════════════════════════════════
# 1. Start Docker services
# ═══════════════════════════════════════════════════════════════════════════
if [ "$SKIP_SETUP" = false ]; then
    log "Starting Docker services..."
    docker compose up -d --wait 2>&1 || {
        warn "docker compose --wait failed, giving extra time..."
        sleep 30
    }

    # Verify each service
    for svc in devpi verdaccio athens reposilite; do
        if docker compose ps "$svc" --format '{{.Health}}' 2>/dev/null | grep -qi healthy; then
            ok "$svc healthy"
        else
            state=$(docker compose ps "$svc" --format '{{.State}}' 2>/dev/null || echo "unknown")
            warn "$svc state: $state (may still be starting)"
        fi
    done

    # ═══════════════════════════════════════════════════════════════════════
    # 2. Populate registries with test packages
    # ═══════════════════════════════════════════════════════════════════════
    log "Populating registries (setup.sh)..."
    bash ./setup.sh
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. Install deps in each target project (generates lockfiles for Syft)
# ═══════════════════════════════════════════════════════════════════════════
log "Installing dependencies in target projects..."

# --- Python: pip install into local venv ---
install_python() {
    log "  Python: installing from PyPI + devpi..."
    cd "$TARGET/python-mixed"

    # Create venv if missing
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    source .venv/bin/activate

    # pip.conf already sets extra-index-url to devpi
    export PIP_CONFIG_FILE="$TARGET/python-mixed/pip.conf"
    export PIP_TRUSTED_HOST=localhost

    pip install -r requirements.txt --quiet 2>&1 && ok "Python deps installed" || {
        fail "Python pip install failed"
        # Show what failed
        pip install -r requirements.txt 2>&1 | tail -5
    }

    # Freeze for Syft (it reads requirements.txt but frozen is more precise)
    pip freeze > requirements-frozen.txt 2>/dev/null || true

    deactivate
}

# --- npm: npm install to get package-lock.json + node_modules ---
install_npm() {
    log "  npm: installing from npmjs + Verdaccio..."
    cd "$TARGET/npm-mixed"

    # .npmrc already routes @company/* to Verdaccio
    export NPM_CONFIG_USERCONFIG="$TARGET/npm-mixed/.npmrc"

    # npm install generates package-lock.json (Syft's primary source)
    npm install --no-audit --no-fund 2>&1 && ok "npm deps installed" || {
        fail "npm install failed"
        npm install 2>&1 | tail -10
    }
}

# --- Go: go mod download to get go.sum ---
install_go() {
    log "  Go: downloading via Athens proxy..."
    cd "$TARGET/go-mixed"

    export GOPROXY="${ATHENS_URL},https://proxy.golang.org,direct"
    export GONOSUMCHECK="go.company.com/*"
    export GONOSUMDB="go.company.com/*"
    export GOFLAGS=""

    # go mod tidy generates/updates go.sum (Syft's primary source)
    go mod tidy 2>&1 && ok "Go deps downloaded" || {
        fail "go mod tidy failed"
        go mod tidy 2>&1 | tail -5
    }
}

# --- Maven: mvn dependency:resolve (generates .m2 cache for Syft) ---
install_maven() {
    log "  Maven: resolving via Reposilite..."
    cd "$TARGET/maven-mixed"

    if ! command -v mvn &>/dev/null; then
        warn "mvn not found — skipping Maven dep resolution"
        warn "Syft can still read pom.xml directly for SBOM"
        return
    fi

    # Use local settings.xml with Reposilite credentials
    mvn dependency:resolve \
        -s "$TARGET/maven-mixed/settings.xml" \
        -q 2>&1 && ok "Maven deps resolved" || {
        warn "Maven resolve failed (Syft will use pom.xml directly)"
    }
}

install_python
install_npm
install_go
install_maven

# ═══════════════════════════════════════════════════════════════════════════
# 4. Verify auth works — quick smoke test each registry
# ═══════════════════════════════════════════════════════════════════════════
log "Verifying registry auth..."

# Python/devpi: check that internal-sdk is accessible
if curl -sf "$DEVPI_URL/testuser/company/+simple/internal-sdk/" | grep -q "internal-sdk"; then
    ok "devpi: internal-sdk accessible"
else
    warn "devpi: internal-sdk not found (setup.sh may have failed)"
fi

# npm/Verdaccio: check that @company/logger is accessible
if curl -sf "$VERDACCIO_URL/@company%2flogger" | grep -q "company/logger"; then
    ok "Verdaccio: @company/logger accessible"
else
    warn "Verdaccio: @company/logger not found"
fi

# Go/Athens: check proxy health
if curl -sf "$ATHENS_URL/healthz" >/dev/null 2>&1; then
    ok "Athens: healthy"
else
    warn "Athens: healthcheck failed"
fi

# Maven/Reposilite: check API
if curl -sf "$REPOSILITE_URL/api/status" >/dev/null 2>&1; then
    ok "Reposilite: healthy"
else
    warn "Reposilite: API not responding"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. Verify lockfiles were generated
# ═══════════════════════════════════════════════════════════════════════════
log "Checking lockfiles..."

[ -f "$TARGET/python-mixed/.venv/lib/"*"/site-packages/internal_sdk.py" ] 2>/dev/null \
    && ok "Python: internal_sdk installed in venv" \
    || warn "Python: internal_sdk not found in venv"

[ -f "$TARGET/npm-mixed/package-lock.json" ] \
    && ok "npm: package-lock.json exists" \
    || fail "npm: package-lock.json MISSING — Syft won't find npm packages"

if [ -f "$TARGET/npm-mixed/package-lock.json" ]; then
    if grep -q "@company/logger" "$TARGET/npm-mixed/package-lock.json"; then
        ok "npm: @company/logger in lockfile"
    else
        warn "npm: @company/logger NOT in lockfile"
    fi
fi

[ -f "$TARGET/go-mixed/go.sum" ] \
    && ok "Go: go.sum exists" \
    || fail "Go: go.sum MISSING — Syft won't find Go modules"

echo ""
log "Registry setup complete. Run tests with:"
echo ""
echo "  cd $(dirname "$SCRIPT_DIR")"
echo "  pytest tests/test_private_registry_integration.py -v"
echo ""
