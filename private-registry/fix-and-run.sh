#!/usr/bin/env bash
# Copyright © 2026 Sthenos Security. All rights reserved.
# fix-and-run.sh — Publish npm packages, install deps, run ALL tests
# One script. Copy-paste one command. Done.
set -euo pipefail

TESTBED="$HOME/src/reach-testbed"
REGISTRY="$TESTBED/private-registry"
VERDACCIO_URL="http://localhost:4873"
NPM_MIXED="$REGISTRY/target-projects/npm-mixed"

echo "========================================"
echo "  STEP 1: Verify Verdaccio is running"
echo "========================================"
if ! curl -sf "$VERDACCIO_URL/-/ping" > /dev/null 2>&1; then
    echo "ERROR: Verdaccio not running on $VERDACCIO_URL"
    echo "Run:  cd $REGISTRY && docker compose up -d --wait"
    exit 1
fi
echo "  OK — Verdaccio responding"

echo ""
echo "========================================"
echo "  STEP 2: Publish @company/* to Verdaccio"
echo "========================================"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Create .npmrc for publishing
cat > "$TMPDIR/.npmrc" << EOF
registry=$VERDACCIO_URL/
//localhost:4873/:_authToken="test-token"
EOF
export NPM_CONFIG_USERCONFIG="$TMPDIR/.npmrc"

# Register user (ignore if exists)
npm adduser --registry "$VERDACCIO_URL" <<< $'testuser\ntest\ntest@test.com' 2>/dev/null || true

# --- @company/logger ---
echo "  Publishing @company/logger..."
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
(cd "$TMPDIR/company-logger" && npm publish --registry "$VERDACCIO_URL" 2>&1) || echo "  (already published or error — continuing)"

# --- @company/http ---
echo "  Publishing @company/http..."
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
(cd "$TMPDIR/company-http" && npm publish --registry "$VERDACCIO_URL" 2>&1) || echo "  (already published or error — continuing)"

# --- @company/internal-utils ---
echo "  Publishing @company/internal-utils..."
mkdir -p "$TMPDIR/company-utils"
cat > "$TMPDIR/company-utils/package.json" << 'EOF'
{
  "name": "@company/internal-utils",
  "version": "3.0.0",
  "description": "Genuine private utilities",
  "main": "index.js"
}
EOF
cat > "$TMPDIR/company-utils/index.js" << 'EOF'
exports.formatId = (id) => `CORP-${id}`;
exports.validateToken = (t) => t.length >= 32;
EOF
(cd "$TMPDIR/company-utils" && npm publish --registry "$VERDACCIO_URL" 2>&1) || echo "  (already published or error — continuing)"

echo ""
echo "========================================"
echo "  STEP 3: npm install in npm-mixed"
echo "========================================"
cd "$NPM_MIXED"
# Clear stale state
rm -rf node_modules package-lock.json
npm install --registry "$VERDACCIO_URL" 2>&1
if [ -f package-lock.json ]; then
    echo "  OK — package-lock.json created"
    echo "  Packages: $(ls node_modules | wc -l | tr -d ' ') installed"
else
    echo "  ERROR: package-lock.json not created"
    exit 1
fi

echo ""
echo "========================================"
echo "  STEP 4: Run ALL integration tests"
echo "========================================"
cd "$TESTBED"
pytest tests/test_private_registry_integration.py -v -s --tb=short 2>&1

echo ""
echo "Done."
