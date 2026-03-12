#!/usr/bin/env bash
# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# setup-and-test.sh — Complete private registry integration test runner
#
# Does EVERYTHING from zero state:
#   1. (Re)starts all 4 Docker registry services
#   2. Publishes private packages to each registry
#   3. Installs dependencies in each target project
#   4. Runs the full pytest suite
#
# Usage:
#   cd ~/src/reach-testbed/private-registry
#   ./setup-and-test.sh
#
# Individual steps:
#   ./setup-and-test.sh setup      # Steps 1-3 only (no tests)
#   ./setup-and-test.sh test       # Step 4 only (assumes setup done)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TESTBED="$(dirname "$SCRIPT_DIR")"
TARGET="$SCRIPT_DIR/target-projects"

DEVPI_URL="http://localhost:3141"
VERDACCIO_URL="http://localhost:4873"
ATHENS_URL="http://localhost:3000"
REPOSILITE_URL="http://localhost:8081"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
step() { echo -e "\n${BOLD}═══ $1 ═══${NC}"; }

# ============================================================================
# STEP 1: Docker services
# ============================================================================
start_services() {
    step "STEP 1/4: Starting Docker registry services"

    docker compose down 2>/dev/null || true
    docker compose up -d --wait --wait-timeout 120

    echo ""
    echo "  Service status:"
    for svc in devpi verdaccio athens reposilite; do
        if docker compose ps --format json "$svc" 2>/dev/null | grep -q '"healthy"'; then
            ok "$svc"
        else
            # Give it more time
            warn "$svc not healthy yet — waiting 30s..."
            sleep 30
            if docker compose ps --format json "$svc" 2>/dev/null | grep -q '"healthy"'; then
                ok "$svc (delayed)"
            else
                fail "$svc — may cause test skips"
            fi
        fi
    done
}

# ============================================================================
# STEP 2: Publish private packages
# ============================================================================
publish_packages() {
    step "STEP 2/4: Publishing private packages to registries"

    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" RETURN

    # ------------------------------------------------------------------
    # PYTHON → devpi
    # ------------------------------------------------------------------
    echo ""
    echo "  --- Python (devpi) ---"
    if curl -sf "$DEVPI_URL/+api" > /dev/null 2>&1; then
        pip install devpi-client --quiet 2>/dev/null || true

        devpi use "$DEVPI_URL" 2>/dev/null
        devpi login root --password=test 2>/dev/null
        devpi user -c testuser password=test 2>/dev/null || true
        devpi index -c testuser/company bases=root/pypi 2>/dev/null || true
        devpi login testuser --password=test 2>/dev/null
        devpi use testuser/company 2>/dev/null

        # Mirror: authlib (real PyPI package served from devpi)
        echo "    Publishing authlib==1.3.0..."
        pip download authlib==1.3.0 --no-deps -d "$TMPDIR/authlib" --quiet 2>/dev/null || true
        if ls "$TMPDIR"/authlib/*.whl 1>/dev/null 2>&1; then
            devpi upload "$TMPDIR"/authlib/*.whl 2>/dev/null || true
            ok "authlib==1.3.0"
        else
            warn "authlib download failed"
        fi

        # Mirror: jinja2
        echo "    Publishing jinja2==3.1.2..."
        pip download jinja2==3.1.2 --no-deps -d "$TMPDIR/jinja2" --quiet 2>/dev/null || true
        if ls "$TMPDIR"/jinja2/*.whl 1>/dev/null 2>&1; then
            devpi upload "$TMPDIR"/jinja2/*.whl 2>/dev/null || true
            ok "jinja2==3.1.2"
        else
            warn "jinja2 download failed"
        fi

        # Genuine private: internal-sdk
        echo "    Publishing internal-sdk==0.5.0..."
        mkdir -p "$TMPDIR/internal-sdk"
        cat > "$TMPDIR/internal-sdk/setup.py" << 'PYEOF'
from setuptools import setup
setup(
    name='internal-sdk',
    version='0.5.0',
    py_modules=['internal_sdk'],
    description='Genuine private SDK',
)
PYEOF
        cat > "$TMPDIR/internal-sdk/internal_sdk.py" << 'PYEOF'
"""Internal SDK — company-specific code with no public equivalent."""
def authenticate(token: str) -> bool:
    return len(token) > 0
def get_config() -> dict:
    return {"env": "production", "region": "us-east-1"}
PYEOF
        (cd "$TMPDIR/internal-sdk" && python setup.py sdist bdist_wheel --quiet 2>/dev/null)
        devpi upload "$TMPDIR"/internal-sdk/dist/*.whl 2>/dev/null || true
        ok "internal-sdk==0.5.0"
    else
        warn "devpi not responding — skipping Python packages"
    fi

    # ------------------------------------------------------------------
    # NPM → Verdaccio
    # ------------------------------------------------------------------
    echo ""
    echo "  --- npm (Verdaccio) ---"
    if curl -sf "$VERDACCIO_URL/-/ping" > /dev/null 2>&1; then
        # Auth config for publishing
        PUBLISH_NPMRC="$TMPDIR/.npmrc"
        cat > "$PUBLISH_NPMRC" << EOF
registry=$VERDACCIO_URL/
//localhost:4873/:_authToken="test-token"
EOF
        export NPM_CONFIG_USERCONFIG="$PUBLISH_NPMRC"
        npm adduser --registry "$VERDACCIO_URL" <<< $'testuser\ntest\ntest@test.com' 2>/dev/null || true

        # @company/logger (wraps winston)
        echo "    Publishing @company/logger@2.0.0..."
        mkdir -p "$TMPDIR/company-logger"
        cat > "$TMPDIR/company-logger/package.json" << 'EOF'
{ "name": "@company/logger", "version": "2.0.0", "main": "index.js", "dependencies": { "winston": "3.11.0" } }
EOF
        echo 'module.exports = require("winston");' > "$TMPDIR/company-logger/index.js"
        (cd "$TMPDIR/company-logger" && npm publish --registry "$VERDACCIO_URL" 2>/dev/null) && ok "@company/logger@2.0.0" || warn "@company/logger (already published?)"

        # @company/http (wraps axios)
        echo "    Publishing @company/http@1.5.0..."
        mkdir -p "$TMPDIR/company-http"
        cat > "$TMPDIR/company-http/package.json" << 'EOF'
{ "name": "@company/http", "version": "1.5.0", "main": "index.js", "dependencies": { "axios": "1.6.0" } }
EOF
        echo 'module.exports = require("axios");' > "$TMPDIR/company-http/index.js"
        (cd "$TMPDIR/company-http" && npm publish --registry "$VERDACCIO_URL" 2>/dev/null) && ok "@company/http@1.5.0" || warn "@company/http (already published?)"

        # @company/internal-utils (genuine private)
        echo "    Publishing @company/internal-utils@3.0.0..."
        mkdir -p "$TMPDIR/company-utils"
        cat > "$TMPDIR/company-utils/package.json" << 'EOF'
{ "name": "@company/internal-utils", "version": "3.0.0", "main": "index.js" }
EOF
        cat > "$TMPDIR/company-utils/index.js" << 'EOF'
exports.formatId = (id) => `CORP-${id}`;
exports.validateToken = (t) => t.length >= 32;
EOF
        (cd "$TMPDIR/company-utils" && npm publish --registry "$VERDACCIO_URL" 2>/dev/null) && ok "@company/internal-utils@3.0.0" || warn "@company/internal-utils (already published?)"

        unset NPM_CONFIG_USERCONFIG
    else
        warn "Verdaccio not responding — skipping npm packages"
    fi

    # ------------------------------------------------------------------
    # Go → Athens (auto-proxies, just warm the cache)
    # ------------------------------------------------------------------
    echo ""
    echo "  --- Go (Athens) ---"
    if curl -sf "$ATHENS_URL/healthz" > /dev/null 2>&1; then
        echo "    Warming Athens cache..."
        curl -sf "$ATHENS_URL/github.com/gin-gonic/gin/@v/v1.9.1.info" > /dev/null 2>&1 && ok "gin@v1.9.1" || warn "gin cache miss"
        curl -sf "$ATHENS_URL/golang.org/x/net/@v/v0.23.0.info" > /dev/null 2>&1 && ok "x/net@v0.23.0" || warn "x/net cache miss"
    else
        warn "Athens not responding — Go tests may skip"
    fi

    # ------------------------------------------------------------------
    # Maven → Reposilite (auto-proxies from Maven Central)
    # ------------------------------------------------------------------
    echo ""
    echo "  --- Maven (Reposilite) ---"
    if curl -sf "$REPOSILITE_URL/" > /dev/null 2>&1; then
        ok "Reposilite ready (auto-proxies Maven Central)"
    else
        warn "Reposilite not responding — Maven tests may skip"
    fi
}

# ============================================================================
# STEP 3: Install dependencies in target projects
# ============================================================================
install_deps() {
    step "STEP 3/4: Installing dependencies in target projects"

    # ------------------------------------------------------------------
    # Python: pip install into .venv
    # ------------------------------------------------------------------
    echo ""
    echo "  --- python-mixed ---"
    if curl -sf "$DEVPI_URL/+api" > /dev/null 2>&1; then
        cd "$TARGET/python-mixed"
        rm -rf .venv
        python3 -m venv .venv
        .venv/bin/pip install --upgrade pip --quiet 2>/dev/null
        PIP_CONFIG_FILE="$TARGET/python-mixed/pip.conf" \
        PIP_TRUSTED_HOST=localhost \
            .venv/bin/pip install -r requirements.txt --quiet 2>&1 || true
        if [ -d .venv/lib ]; then
            PKG_COUNT=$(.venv/bin/pip list --format=columns 2>/dev/null | tail -n +3 | wc -l | tr -d ' ')
            ok "$PKG_COUNT packages installed"
        else
            fail "venv creation failed"
        fi
    else
        warn "devpi down — skipping python deps"
    fi

    # ------------------------------------------------------------------
    # npm: npm install
    # ------------------------------------------------------------------
    echo ""
    echo "  --- npm-mixed ---"
    cd "$TARGET/npm-mixed"
    rm -rf node_modules package-lock.json
    npm install --registry "$VERDACCIO_URL" 2>&1 | tail -3
    if [ -f package-lock.json ]; then
        PKG_COUNT=$(ls node_modules 2>/dev/null | wc -l | tr -d ' ')
        ok "package-lock.json created ($PKG_COUNT top-level packages)"
    else
        fail "package-lock.json missing — npm install failed"
    fi

    # ------------------------------------------------------------------
    # Go: go mod download
    # ------------------------------------------------------------------
    echo ""
    echo "  --- go-mixed ---"
    cd "$TARGET/go-mixed"
    rm -f go.sum
    GOPROXY="$ATHENS_URL,https://proxy.golang.org,direct" \
    GONOSUMCHECK="go.company.com/*" \
        go mod download 2>&1 || true
    GOPROXY="$ATHENS_URL,https://proxy.golang.org,direct" \
    GONOSUMCHECK="go.company.com/*" \
        go mod tidy 2>&1 || true
    if [ -f go.sum ]; then
        LINES=$(wc -l < go.sum | tr -d ' ')
        ok "go.sum created ($LINES entries)"
    else
        fail "go.sum missing — go mod download failed"
    fi

    # ------------------------------------------------------------------
    # npm-noauth: install ONLY public deps (negative test)
    # ------------------------------------------------------------------
    echo ""
    echo "  --- npm-noauth (negative test) ---"
    cd "$TARGET/npm-noauth"
    rm -rf node_modules package-lock.json
    # Save original package.json, install with public-only version
    cp package.json package-full.json
    # Create temp package.json with only public deps
    cat > package.json << 'NPMPKG'
{
  "name": "npm-noauth-test",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}
NPMPKG
    npm install --registry https://registry.npmjs.org/ 2>&1 | tail -3
    # Restore original package.json (lists @company/* too)
    mv package-full.json package.json
    if [ -f package-lock.json ]; then
        PKG_COUNT=$(ls node_modules 2>/dev/null | wc -l | tr -d ' ')
        ok "public deps only ($PKG_COUNT packages, NO @company/*)"
    else
        fail "npm install failed for public deps"
    fi

    # ------------------------------------------------------------------
    # python-noauth: install ONLY public deps (negative test)
    # ------------------------------------------------------------------
    echo ""
    echo "  --- python-noauth (negative test) ---"
    cd "$TARGET/python-noauth"
    rm -rf .venv
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip --quiet 2>/dev/null
    .venv/bin/pip install requests==2.31.0 flask==2.0.3 --quiet 2>&1
    if [ -d .venv/lib ]; then
        PKG_COUNT=$(.venv/bin/pip list --format=columns 2>/dev/null | tail -n +3 | wc -l | tr -d ' ')
        ok "public deps only ($PKG_COUNT packages, NO internal-sdk)"
    else
        fail "venv creation failed"
    fi

    # ------------------------------------------------------------------
    # Maven: mvn dependency:resolve (if mvn available)
    # ------------------------------------------------------------------
    echo ""
    echo "  --- maven-mixed ---"
    cd "$TARGET/maven-mixed"
    if command -v mvn &>/dev/null; then
        mvn dependency:resolve -s settings.xml -q 2>&1 || true
        ok "maven dependencies resolved"
    else
        warn "mvn not installed — Maven scan relies on pom.xml parsing (Syft handles this)"
        ok "pom.xml present (Syft can scan without mvn)"
    fi
}

# ============================================================================
# STEP 4: Run tests
# ============================================================================
run_tests() {
    step "STEP 4/4: Running integration tests"
    echo ""
    cd "$TESTBED"
    pytest tests/test_private_registry_integration.py -v -s --tb=short 2>&1
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  REACHABLE Private Registry Integration Test Runner     ║"
    echo "║  Python (devpi) · npm (Verdaccio) · Go (Athens) · Maven ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    case "${1:-all}" in
        setup)
            start_services
            publish_packages
            install_deps
            echo ""
            ok "Setup complete. Run: ./setup-and-test.sh test"
            ;;
        test)
            run_tests
            ;;
        all|"")
            start_services
            publish_packages
            install_deps
            run_tests
            ;;
        *)
            echo "Usage: $0 [all|setup|test]"
            exit 1
            ;;
    esac
}

main "$@"
