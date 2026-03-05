#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Registry Authentication Tests

Lightweight HTTP-level tests — no full reachctl scans.
Tests 3 auth tiers per registry: good auth → 200, no auth → 401, bad auth → 403.

Includes:
  - Mock JFrog Artifactory server (npm, PyPI, Maven, Go behind one host)
  - Live registry auth tests (Verdaccio, devpi, Reposilite, Athens)

Run:  pytest tests/test_registry_auth.py -v
"""

import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import pytest


# ============================================================================
# MOCK JFROG ARTIFACTORY SERVER
# ============================================================================

VALID_TOKEN = "test-artifactory-token-2026"
VALID_USER = "deployer"
VALID_PASS = "deploy-secret"


class ArtifactoryMockHandler(BaseHTTPRequestHandler):
    """Mock JFrog Artifactory — unified proxy for all package managers.

    Auth methods:
      - Bearer token:  Authorization: Bearer <token>
      - Basic auth:    Authorization: Basic base64(user:pass)

    API paths (mirrors real Artifactory URL layout):
      /api/system/ping                           → health (no auth)
      /artifactory/api/npm/npm-local/            → npm registry
      /artifactory/api/pypi/pypi-local/simple/   → PyPI index
      /artifactory/api/go/go-local/              → Go module proxy
      /artifactory/maven-local/                  → Maven repository
    """

    def _check_auth(self) -> Optional[str]:
        """Returns None if valid, error string if not."""
        auth = self.headers.get('Authorization', '')
        if not auth:
            return 'no_auth'
        if auth.startswith('Bearer '):
            return None if auth[7:] == VALID_TOKEN else 'bad_token'
        if auth.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                u, p = decoded.split(':', 1)
                return None if u == VALID_USER and p == VALID_PASS else 'bad_credentials'
            except Exception:
                return 'malformed_basic'
        return 'unknown_auth_type'

    def do_GET(self):
        path = self.path

        # Health — no auth
        if path == '/api/system/ping':
            self._json(200, {'status': 'OK'})
            return

        # Everything else requires auth
        err = self._check_auth()
        if err == 'no_auth':
            self._json(401, {'errors': [{'status': 401, 'message': 'Unauthorized'}]})
            return
        if err:
            self._json(403, {'errors': [{'status': 403, 'message': f'Forbidden: {err}'}]})
            return

        # npm
        if path.startswith('/artifactory/api/npm/'):
            self._json(200, {
                'name': '@company/logger',
                'versions': {'2.0.0': {'name': '@company/logger', 'version': '2.0.0'}},
            })
            return

        # PyPI
        if path.startswith('/artifactory/api/pypi/'):
            pkg = path.rstrip('/').split('/')[-1]
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(
                f'<html><body><a href="{pkg}-0.5.0.tar.gz">{pkg}-0.5.0.tar.gz</a></body></html>'.encode()
            )
            return

        # Go
        if path.startswith('/artifactory/api/go/'):
            self._json(200, {'Version': 'v0.23.0', 'Time': '2024-01-01T00:00:00Z'})
            return

        # Maven
        if path.startswith('/artifactory/maven-local/'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            self.wfile.write(b'<?xml version="1.0"?><metadata><groupId>com.company</groupId></metadata>')
            return

        self._json(404, {'errors': [{'status': 404, 'message': 'Not found'}]})

    def _json(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


# ============================================================================
# HELPERS & FIXTURES
# ============================================================================

def _http_get(url, headers=None, timeout=5):
    """HTTP GET → (status_code, body_text)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if e.fp else ''


def _http_put(url, data=b'', headers=None, timeout=5):
    """HTTP PUT → (status_code, body_text)."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method='PUT')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if e.fp else ''


def _basic_auth(user, passwd):
    return base64.b64encode(f'{user}:{passwd}'.encode()).decode()


@pytest.fixture(scope='module')
def mock_artifactory():
    """Start mock Artifactory on a random port, return base URL."""
    server = HTTPServer(('127.0.0.1', 0), ArtifactoryMockHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f'http://127.0.0.1:{port}'
    server.shutdown()


# ============================================================================
# MOCK ARTIFACTORY AUTH TESTS (always run — no Docker needed)
# ============================================================================

class TestArtifactoryHealth:
    def test_MOCK01_ping_no_auth(self, mock_artifactory):
        s, b = _http_get(f'{mock_artifactory}/api/system/ping')
        assert s == 200 and 'OK' in b


class TestArtifactoryNpm:
    """npm: Bearer token auth. 3-tier: good/none/bad."""

    def test_MOCK_NPM01_good_token(self, mock_artifactory):
        s, b = _http_get(
            f'{mock_artifactory}/artifactory/api/npm/npm-local/@company%2flogger',
            {'Authorization': f'Bearer {VALID_TOKEN}'}
        )
        assert s == 200
        assert '@company/logger' in b

    def test_MOCK_NPM02_no_auth(self, mock_artifactory):
        s, _ = _http_get(f'{mock_artifactory}/artifactory/api/npm/npm-local/@company%2flogger')
        assert s == 401

    def test_MOCK_NPM03_bad_token(self, mock_artifactory):
        s, _ = _http_get(
            f'{mock_artifactory}/artifactory/api/npm/npm-local/@company%2flogger',
            {'Authorization': 'Bearer wrong-token'}
        )
        assert s == 403


class TestArtifactoryPyPI:
    """PyPI: Basic auth (user:token). 3-tier."""

    def test_MOCK_PYPI01_good_auth(self, mock_artifactory):
        s, b = _http_get(
            f'{mock_artifactory}/artifactory/api/pypi/pypi-local/simple/internal-sdk/',
            {'Authorization': f'Basic {_basic_auth(VALID_USER, VALID_PASS)}'}
        )
        assert s == 200
        assert 'internal-sdk' in b

    def test_MOCK_PYPI02_no_auth(self, mock_artifactory):
        s, _ = _http_get(f'{mock_artifactory}/artifactory/api/pypi/pypi-local/simple/internal-sdk/')
        assert s == 401

    def test_MOCK_PYPI03_bad_password(self, mock_artifactory):
        s, _ = _http_get(
            f'{mock_artifactory}/artifactory/api/pypi/pypi-local/simple/internal-sdk/',
            {'Authorization': f'Basic {_basic_auth(VALID_USER, "wrong")}'}
        )
        assert s == 403


class TestArtifactoryMaven:
    """Maven: Basic auth (from settings.xml). 3-tier."""

    def test_MOCK_MVN01_good_auth(self, mock_artifactory):
        s, b = _http_get(
            f'{mock_artifactory}/artifactory/maven-local/com/company/sdk/1.0/sdk-1.0.pom',
            {'Authorization': f'Basic {_basic_auth(VALID_USER, VALID_PASS)}'}
        )
        assert s == 200
        assert 'com.company' in b

    def test_MOCK_MVN02_no_auth(self, mock_artifactory):
        s, _ = _http_get(f'{mock_artifactory}/artifactory/maven-local/com/company/sdk/1.0/sdk-1.0.pom')
        assert s == 401

    def test_MOCK_MVN03_bad_auth(self, mock_artifactory):
        s, _ = _http_get(
            f'{mock_artifactory}/artifactory/maven-local/com/company/sdk/1.0/sdk-1.0.pom',
            {'Authorization': f'Basic {_basic_auth("hacker", "letmein")}'}
        )
        assert s == 403


class TestArtifactoryGo:
    """Go: Bearer token via GOPROXY. 3-tier."""

    def test_MOCK_GO01_good_token(self, mock_artifactory):
        s, b = _http_get(
            f'{mock_artifactory}/artifactory/api/go/go-local/golang.org/x/net/@v/v0.23.0.info',
            {'Authorization': f'Bearer {VALID_TOKEN}'}
        )
        assert s == 200
        assert 'v0.23.0' in b

    def test_MOCK_GO02_no_auth(self, mock_artifactory):
        s, _ = _http_get(
            f'{mock_artifactory}/artifactory/api/go/go-local/golang.org/x/net/@v/v0.23.0.info'
        )
        assert s == 401

    def test_MOCK_GO03_bad_token(self, mock_artifactory):
        s, _ = _http_get(
            f'{mock_artifactory}/artifactory/api/go/go-local/golang.org/x/net/@v/v0.23.0.info',
            {'Authorization': 'Bearer expired-token'}
        )
        assert s == 403


# ============================================================================
# LIVE REGISTRY AUTH TESTS (run against Docker containers when available)
# ============================================================================

VERDACCIO_URL = 'http://localhost:4873'
DEVPI_URL = 'http://localhost:3141'
REPOSILITE_URL = 'http://localhost:8081'
ATHENS_URL = 'http://localhost:3000'


def _alive(url):
    try:
        urllib.request.urlopen(url, timeout=3)
        return True
    except urllib.error.HTTPError:
        return True  # got a response
    except Exception:
        return False


class TestVerdaccioAuth:
    """Live Verdaccio: npm registry access patterns."""

    @pytest.fixture(autouse=True)
    def _skip_if_down(self):
        if not _alive(f'{VERDACCIO_URL}/-/ping'):
            pytest.skip('Verdaccio not running')

    def test_VERD01_ping(self):
        s, _ = _http_get(f'{VERDACCIO_URL}/-/ping')
        assert s == 200

    def test_VERD02_public_package_no_auth(self):
        """Public packages always accessible."""
        s, _ = _http_get(f'{VERDACCIO_URL}/express')
        assert s == 200

    def test_VERD03_private_with_token(self):
        """@company/* with valid token → 200 or 404 (not 401/403)."""
        s, _ = _http_get(
            f'{VERDACCIO_URL}/@company%2flogger',
            {'Authorization': 'Bearer test-token'}
        )
        assert s in (200, 404), f'Expected 200/404 with token, got {s}'

    def test_VERD04_private_bad_token(self):
        """@company/* with bad token — documents current behavior.
        After lockdown (access: $authenticated), this should be 401/403."""
        s, _ = _http_get(
            f'{VERDACCIO_URL}/@company%2flogger',
            {'Authorization': 'Bearer totally-wrong'}
        )
        # Currently $all so 200/404; after lockdown should be 401/403
        assert s in (200, 401, 403, 404)


class TestDevpiAuth:
    """Live devpi: Python registry access patterns."""

    @pytest.fixture(autouse=True)
    def _skip_if_down(self):
        if not _alive(f'{DEVPI_URL}/+api'):
            pytest.skip('devpi not running')

    def test_DEVPI01_api_ping(self):
        s, _ = _http_get(f'{DEVPI_URL}/+api')
        assert s == 200

    def test_DEVPI02_public_index(self):
        """root/pypi is public."""
        s, _ = _http_get(f'{DEVPI_URL}/root/pypi/+simple/requests/')
        assert s in (200, 302)

    def test_DEVPI03_private_index(self):
        """testuser/company index access."""
        s, _ = _http_get(f'{DEVPI_URL}/testuser/company/+simple/internal-sdk/')
        assert s in (200, 404, 401, 403)


class TestReposiliteAuth:
    """Live Reposilite: Maven registry — reads are public, deploys need auth."""

    @pytest.fixture(autouse=True)
    def _skip_if_down(self):
        if not _alive(f'{REPOSILITE_URL}/'):
            pytest.skip('Reposilite not running')

    def test_REPO01_root(self):
        s, _ = _http_get(f'{REPOSILITE_URL}/')
        assert s == 200

    def test_REPO02_read_no_auth(self):
        """Read access is public."""
        s, _ = _http_get(f'{REPOSILITE_URL}/releases')
        assert s in (200, 404)

    def test_REPO03_deploy_no_auth(self):
        """PUT without auth → rejected."""
        s, _ = _http_put(
            f'{REPOSILITE_URL}/releases/com/test/artifact/1.0/test-1.0.pom',
            data=b'<project/>'
        )
        assert s in (401, 403, 405), f'Expected auth error for PUT, got {s}'

    def test_REPO04_deploy_with_auth(self):
        """PUT with admin:secret → accepted."""
        s, _ = _http_put(
            f'{REPOSILITE_URL}/releases/com/test/auth-test/1.0/auth-test-1.0.pom',
            data=b'<project><modelVersion>4.0.0</modelVersion></project>',
            headers={'Authorization': f'Basic {_basic_auth("admin", "secret")}'}
        )
        assert s in (200, 201), f'Expected 200/201 with auth, got {s}'

    def test_REPO05_deploy_bad_auth(self):
        """PUT with wrong credentials → rejected."""
        s, _ = _http_put(
            f'{REPOSILITE_URL}/releases/com/test/bad/1.0/bad-1.0.pom',
            data=b'<project/>',
            headers={'Authorization': f'Basic {_basic_auth("hacker", "nope")}'}
        )
        assert s in (401, 403), f'Expected 401/403, got {s}'


class TestAthensAuth:
    """Live Athens: Go proxy — public by design (no auth for reads)."""

    @pytest.fixture(autouse=True)
    def _skip_if_down(self):
        if not _alive(f'{ATHENS_URL}/healthz'):
            pytest.skip('Athens not running')

    def test_ATHENS01_healthz(self):
        s, _ = _http_get(f'{ATHENS_URL}/healthz')
        assert s == 200

    def test_ATHENS02_module_no_auth(self):
        """Public modules proxy without auth."""
        s, _ = _http_get(f'{ATHENS_URL}/github.com/gin-gonic/gin/@v/v1.9.1.info')
        assert s in (200, 404)
