#!/usr/bin/env bash
# setup.sh — Populate private registries with test packages (idempotent)
#
# Creates synthetic private packages that:
#   - Mirror: exact same content as a public package (hash match)
#   - Wrapper: wraps a public package under a private name
#   - Genuine: unique private code with no upstream match
#
# Usage:
#   docker compose up -d --wait
#   ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DEVPI_URL="http://localhost:3141"
VERDACCIO_URL="http://localhost:4873"
ATHENS_URL="http://localhost:3000"
REPOSILITE_URL="http://localhost:8081"

echo "=== Private Registry Setup ==="
echo ""

# ---------------------------------------------------------------------------
# Python / devpi
# ---------------------------------------------------------------------------
setup_python() {
    echo "--- Python (devpi) ---"

    pip install devpi-client --quiet 2>/dev/null || true

    # Wait for devpi — first boot indexes 753K PyPI projects (~90s, ~1.5GB RAM)
    echo "  Waiting for devpi to be ready..."
    for i in $(seq 1 60); do
        if curl -sf "$DEVPI_URL/+api" > /dev/null 2>&1; then
            echo "  devpi is responding"
            break
        fi
        if [ "$i" -eq 60 ]; then
            echo "  ERROR: devpi not responding after 120s. Check: docker logs private-registry-devpi-1"
            return 1
        fi
        sleep 2
    done

    devpi use "$DEVPI_URL"
    devpi login root --password=test
    devpi user -c testuser password=test 2>/dev/null || true
    # Create index as root (testuser lacks create permission)
    devpi index -c testuser/company bases=root/pypi 2>/dev/null || true
    devpi login testuser --password=test
    devpi use testuser/company

    TMPDIR=$(mktemp -d)

    # --- Mirror package: authlib (same hash as public PyPI) ---
    echo "  Publishing authlib mirror..."
    pip download authlib==1.3.0 --no-deps -d "$TMPDIR/authlib" --quiet 2>/dev/null || true
    if ls "$TMPDIR"/authlib/*.whl 1>/dev/null 2>&1; then
        devpi upload "$TMPDIR"/authlib/*.whl 2>/dev/null || true
    fi

    # --- Mirror package: jinja2 (same hash as public PyPI) ---
    echo "  Publishing jinja2 mirror..."
    pip download jinja2==3.1.2 --no-deps -d "$TMPDIR/jinja2" --quiet 2>/dev/null || true
    if ls "$TMPDIR"/jinja2/*.whl 1>/dev/null 2>&1; then
        devpi upload "$TMPDIR"/jinja2/*.whl 2>/dev/null || true
    fi

    # --- Genuine private: internal-sdk ---
    echo "  Publishing internal-sdk (genuine private)..."
    mkdir -p "$TMPDIR/internal-sdk"
    cat > "$TMPDIR/internal-sdk/setup.py" << 'PYEOF'
from setuptools import setup
setup(
    name='internal-sdk',
    version='0.5.0',
    py_modules=['internal_sdk'],
    description='Genuine private SDK — no public upstream',
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

    rm -rf "$TMPDIR"
    echo "  Python setup complete"
}

# ---------------------------------------------------------------------------
# npm / Verdaccio
# ---------------------------------------------------------------------------
setup_npm() {
    echo "--- npm (Verdaccio) ---"

    TMPDIR=$(mktemp -d)

    # Create a Verdaccio user for publishing
    # Use npm adduser with expect-like approach
    cat > "$TMPDIR/.npmrc" << EOF
registry=$VERDACCIO_URL/
//localhost:4873/:_authToken="test-token"
EOF

    # Register user (may fail if already exists — that's OK)
    npm adduser --registry "$VERDACCIO_URL" <<< $'testuser\ntest\ntest@test.com' 2>/dev/null || true

    # --- Mirror: @company/logger (wraps winston verbatim) ---
    echo "  Publishing @company/logger (wraps winston)..."
    mkdir -p "$TMPDIR/company-logger"
    cat > "$TMPDIR/company-logger/package.json" << 'EOF'
{
  "name": "@company/logger",
  "version": "2.0.0",
  "description": "Company logger — wraps winston",
  "main": "index.js",
  "dependencies": { "winston": "3.11.0" }
}
EOF
    echo 'module.exports = require("winston");' > "$TMPDIR/company-logger/index.js"
    (cd "$TMPDIR/company-logger" && npm publish --registry "$VERDACCIO_URL" 2>/dev/null) || true

    # --- Mirror: @company/http (wraps axios) ---
    echo "  Publishing @company/http (wraps axios)..."
    mkdir -p "$TMPDIR/company-http"
    cat > "$TMPDIR/company-http/package.json" << 'EOF'
{
  "name": "@company/http",
  "version": "1.5.0",
  "description": "Company HTTP client — wraps axios",
  "main": "index.js",
  "dependencies": { "axios": "1.6.0" }
}
EOF
    echo 'module.exports = require("axios");' > "$TMPDIR/company-http/index.js"
    (cd "$TMPDIR/company-http" && npm publish --registry "$VERDACCIO_URL" 2>/dev/null) || true

    # --- Genuine private: @company/internal-utils ---
    echo "  Publishing @company/internal-utils (genuine private)..."
    mkdir -p "$TMPDIR/company-utils"
    cat > "$TMPDIR/company-utils/package.json" << 'EOF'
{
  "name": "@company/internal-utils",
  "version": "3.0.0",
  "description": "Genuine private utilities — no public upstream",
  "main": "index.js"
}
EOF
    cat > "$TMPDIR/company-utils/index.js" << 'EOF'
// Genuine private — company-specific utilities
exports.formatId = (id) => `CORP-${id}`;
exports.validateToken = (t) => t.length >= 32;
EOF
    (cd "$TMPDIR/company-utils" && npm publish --registry "$VERDACCIO_URL" 2>/dev/null) || true

    rm -rf "$TMPDIR"
    echo "  npm setup complete"
}

# ---------------------------------------------------------------------------
# Go / Athens  (Athens auto-proxies public modules; private modules need setup)
# ---------------------------------------------------------------------------
setup_go() {
    echo "--- Go (Athens) ---"
    # Athens auto-caches public modules on first request.
    # Pre-warm the cache for our test modules.
    echo "  Warming Athens cache for golang.org/x/crypto..."
    curl -sf "$ATHENS_URL/github.com/gin-gonic/gin/@v/v1.9.1.info" > /dev/null 2>&1 || true
    curl -sf "$ATHENS_URL/golang.org/x/net/@v/v0.23.0.info" > /dev/null 2>&1 || true
    curl -sf "$ATHENS_URL/golang.org/x/crypto/@v/v0.21.0.info" > /dev/null 2>&1 || true
    echo "  Go setup complete (Athens auto-proxies public modules)"
}

# ---------------------------------------------------------------------------
# Maven / Reposilite
# ---------------------------------------------------------------------------
setup_maven() {
    echo "--- Maven (Reposilite) ---"

    # Reposilite auto-creates 'releases' and 'snapshots' repositories on first start.
    # The --token admin:secret in docker-compose.yml provides API access.
    # Just verify the service is up.
    for i in $(seq 1 15); do
        if curl -sf "$REPOSILITE_URL/api/status" > /dev/null 2>&1; then
            echo "  Reposilite is ready"
            break
        fi
        sleep 2
    done

    if ! curl -sf "$REPOSILITE_URL/api/status" > /dev/null 2>&1; then
        echo "  WARNING: Reposilite not reachable. Maven tests may be skipped."
        echo "  Maven setup skipped"
        return
    fi

    echo "  Maven setup complete (Reposilite auto-provisions 'releases' repo)"
}

# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------
echo "Waiting for services to be healthy..."
docker compose ps --format json | head -5

setup_python
setup_npm
setup_go
setup_maven

echo ""
echo "=== Setup complete ==="
echo "  devpi:      $DEVPI_URL/testuser/company/+simple/"
echo "  Verdaccio: $VERDACCIO_URL"
echo "  Athens:    $ATHENS_URL"
echo "  Reposilite: $REPOSILITE_URL"
echo ""
echo "Run tests:  pytest ../tests/test_purl_resolver_integration.py -v"
