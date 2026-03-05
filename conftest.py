#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Pytest fixtures for private registry integration tests.

Runs `reachctl scan` against target projects that pull from both public
registries and local Docker-based private registries (devpi, Verdaccio,
Athens, Reposilite).

Pre-requisites:
    - reachctl on PATH or in reach-core venv
    - Docker services running: cd private-registry && docker compose up -d --wait && ./setup.sh
"""

import gzip
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVPI_URL   = os.environ.get('DEVPI_URL',   'http://localhost:3141')
VERDACCIO_URL = os.environ.get('VERDACCIO_URL', 'http://localhost:4873')
ATHENS_URL  = os.environ.get('ATHENS_URL',  'http://localhost:3000')
REPOSILITE_URL = os.environ.get('REPOSILITE_URL', 'http://localhost:8081')

INFRA_DIR = Path(__file__).parent / 'private-registry'
TARGET_PROJECTS = INFRA_DIR / 'target-projects'
REACH_CORE = Path(__file__).parent.parent / 'reach-core'
REGISTRIES_TEST_YAML = INFRA_DIR / 'registries-test.yaml'
REGISTRIES_LIVE_PATH = Path.home() / '.reachable' / 'registries.yaml'


# ---------------------------------------------------------------------------
# ScanResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Everything a test needs from one reachctl scan run."""
    exit_code: int
    stdout: str
    stderr: str
    output_dir: Path                          # --output root
    scan_dir: Path                            # actual session dir with sbom/vulns
    repo_db_path: Optional[Path] = None
    scan_id: Optional[int] = None
    sbom: Optional[Dict] = None
    vulns: Optional[Dict] = None
    scan_log: str = ""
    scan_manifest: Optional[Dict] = None
    provenance: Optional[Dict] = None
    scan_plan: Optional[Dict] = None
    db_scan_row: Optional[Dict] = None
    db_findings: List[Dict] = field(default_factory=list)
    db_ai_findings: List[Dict] = field(default_factory=list)
    db_dlp_findings: List[Dict] = field(default_factory=list)
    db_unresolved: List[Dict] = field(default_factory=list)
    db_sandbox_cache: List[Dict] = field(default_factory=list)
    libs_cloned: List[str] = field(default_factory=list)
    raw_files: Dict[str, Any] = field(default_factory=dict)

    # --- Convenience properties ---

    @property
    def completed(self) -> bool:
        return self.db_scan_row is not None and self.db_scan_row.get('status') == 'complete'

    @property
    def failed(self) -> bool:
        return self.db_scan_row is not None and self.db_scan_row.get('status') == 'failed'

    @property
    def sbom_artifact_names(self) -> List[str]:
        if not self.sbom:
            return []
        return [a.get('name', '') for a in self.sbom.get('artifacts', [])]

    @property
    def sbom_purls(self) -> List[str]:
        if not self.sbom:
            return []
        return [a.get('purl', '') for a in self.sbom.get('artifacts', []) if a.get('purl')]

    @property
    def cve_findings(self) -> List[Dict]:
        return [f for f in self.db_findings if f['finding_type'] == 'cve']

    @property
    def cwe_findings(self) -> List[Dict]:
        return [f for f in self.db_findings if f['finding_type'] == 'cwe']

    @property
    def secret_findings(self) -> List[Dict]:
        return [f for f in self.db_findings if f['finding_type'] == 'secret']

    @property
    def malware_findings(self) -> List[Dict]:
        return [f for f in self.db_findings if f['finding_type'] in ('malware', 'suspicious')]

    @property
    def config_findings(self) -> List[Dict]:
        return [f for f in self.db_findings if f['finding_type'] == 'config']

    @property
    def cve_packages(self) -> set:
        return {f['package_name'] for f in self.cve_findings if f.get('package_name')}

    def findings_for_package(self, pkg_name: str) -> List[Dict]:
        return [f for f in self.db_findings
                if pkg_name.lower() in (f.get('package_name') or '').lower()]

    def log_contains(self, pattern: str) -> bool:
        """Check scan.log for a regex pattern (case-insensitive)."""
        return bool(re.search(pattern, self.scan_log, re.IGNORECASE))

    def log_has_fatal(self) -> bool:
        """Check for fatal tool failures in scan.log."""
        fatal_patterns = [
            r'FATAL',
            r'syft.*failed|failed.*syft',
            r'grype.*failed|failed.*grype',
            r'semgrep.*error.*fatal',
            r'guarddog.*crash',
            r'tree-sitter.*segfault',
            r'Traceback \(most recent call last\)',
        ]
        for p in fatal_patterns:
            if re.search(p, self.scan_log, re.IGNORECASE):
                return True
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_service(url: str) -> bool:
    """Return True if the service is reachable (any HTTP response counts)."""
    try:
        import urllib.request
        import urllib.error
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.HTTPError:
        # 401/403/404 still means the service is running
        return True
    except Exception:
        return False


def _find_reachctl() -> Optional[Path]:
    """Find reachctl binary — which(PATH) first, then known locations."""
    # Prefer PATH lookup (verifies the binary is actually executable)
    on_path = shutil.which('reachctl')
    if on_path:
        return Path(on_path)
    # Fallback: known locations, verified executable
    candidates = [
        Path.home() / '.reachable' / 'venv' / 'bin' / 'reachctl',
        REACH_CORE / 'venv' / 'bin' / 'reachctl',
    ]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    return None


def _load_json_or_gz(path: Path) -> Optional[Dict]:
    """Load JSON, trying .gz variant if plain file missing."""
    if path.exists():
        return json.loads(path.read_text())
    gz = path.with_suffix(path.suffix + '.gz')
    if gz.exists():
        return json.loads(gzip.decompress(gz.read_bytes()).decode())
    return None


def _query_repo_db(db_path: Path, scan_id: int = None) -> Dict[str, Any]:
    """Query repo.db for scan data."""
    result = {'scan_row': None, 'findings': [], 'ai_findings': [],
              'dlp_findings': [], 'unresolved': [], 'sandbox_cache': [],
              'scan_id': None}
    if not db_path or not db_path.exists():
        return result

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Latest scan (or specific scan_id)
    if scan_id:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    else:
        row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()

    if not row:
        conn.close()
        return result

    sid = row['id']
    result['scan_row'] = dict(row)
    result['scan_id'] = sid

    # Main findings
    result['findings'] = [dict(r) for r in
        conn.execute("SELECT * FROM findings WHERE scan_id = ?", (sid,)).fetchall()]

    # AI findings
    try:
        result['ai_findings'] = [dict(r) for r in
            conn.execute("SELECT * FROM ai_findings WHERE scan_id = ?", (sid,)).fetchall()]
    except sqlite3.OperationalError:
        pass

    # DLP findings
    try:
        result['dlp_findings'] = [dict(r) for r in
            conn.execute("SELECT * FROM dlp_findings WHERE scan_id = ?", (sid,)).fetchall()]
    except sqlite3.OperationalError:
        pass

    # Unresolved packages
    try:
        result['unresolved'] = [dict(r) for r in
            conn.execute("SELECT * FROM unresolved_packages WHERE scan_id = ?", (sid,)).fetchall()]
    except sqlite3.OperationalError:
        pass

    # Sandbox cache (not per-scan but useful to check)
    try:
        result['sandbox_cache'] = [dict(r) for r in
            conn.execute("SELECT * FROM sandbox_cache ORDER BY tested_at DESC LIMIT 50").fetchall()]
    except sqlite3.OperationalError:
        pass

    conn.close()
    return result


def _find_scan_session_dir(output_dir: Path) -> Path:
    """Walk output dir to find the actual scan session (contains sbom.json*)."""
    for candidate in output_dir.rglob('sbom.json*'):
        return candidate.parent
    for candidate in output_dir.rglob('scan.log'):
        return candidate.parent
    return output_dir


def _find_repo_db(output_dir: Path, target_dir: Path) -> Optional[Path]:
    """Find repo.db — either in output dir or in ~/.reachable/scans/{slug}/."""
    # Check output tree first
    for candidate in output_dir.rglob('repo.db'):
        return candidate

    # Check ~/.reachable/scans/
    scans_root = Path.home() / '.reachable' / 'scans'
    if scans_root.exists():
        for slug_dir in scans_root.iterdir():
            db = slug_dir / 'repo.db'
            if db.exists():
                # Match by target dir name in slug
                target_name = target_dir.name.lower()
                if target_name in slug_dir.name.lower():
                    return db
        # Fallback: most recently modified repo.db
        dbs = sorted(scans_root.rglob('repo.db'), key=lambda p: p.stat().st_mtime, reverse=True)
        if dbs:
            return dbs[0]
    return None


def _collect_raw_files(raw_dir: Path) -> Dict[str, Any]:
    """Load all raw/*.json files into a dict."""
    result = {}
    if not raw_dir.exists():
        return result
    for f in raw_dir.iterdir():
        if f.suffix == '.json':
            try:
                result[f.stem] = json.loads(f.read_text())
            except Exception:
                result[f.stem] = None
        elif f.name.endswith('.json.gz'):
            try:
                result[f.stem.replace('.json', '')] = json.loads(
                    gzip.decompress(f.read_bytes()).decode())
            except Exception:
                result[f.stem] = None
    return result


def _list_cloned_libs(libs_dir: Path) -> List[str]:
    """List library directories under the session libs/ folder."""
    if not libs_dir.exists():
        return []
    return [d.name for d in libs_dir.iterdir() if d.is_dir()]


def _run_reachctl_scan(reachctl: Path, target_dir: Path, tmp_dir: Path,
                        extra_args: List[str] = None,
                        extra_env: Dict[str, str] = None) -> ScanResult:
    """Run reachctl scan and collect ALL outputs into a ScanResult."""
    output_dir = tmp_dir / 'output'
    output_dir.mkdir(exist_ok=True)

    cmd = [str(reachctl), 'scan', str(target_dir),
           '--debug', '--output', str(output_dir)]
    if extra_args:
        cmd.extend(extra_args)

    env = os.environ.copy()
    # reachctl path is absolute from the fixture, no PATH manipulation needed.
    # Add the reachctl's parent dir to PATH so it can find sibling tools.
    reachctl_dir = reachctl.parent
    env['PATH'] = f"{reachctl_dir}:{env.get('PATH', '')}"

    # Inject registry auth / proxy env per ecosystem
    if extra_env:
        env.update(extra_env)

    # Stream to log files so progress is visible via `tail -f` or `pytest -s`
    stdout_log = tmp_dir / 'reachctl-stdout.log'
    stderr_log = tmp_dir / 'reachctl-stderr.log'
    print(f"\n  >> reachctl scan {target_dir.name} "
          f"(timeout 300s, logs: {tmp_dir}/reachctl-*.log)",
          file=sys.stderr, flush=True)

    with open(stdout_log, 'w') as fout, open(stderr_log, 'w') as ferr:
        proc = subprocess.run(cmd, stdout=fout, stderr=ferr, text=True,
                              timeout=300, env=env, cwd=str(target_dir))

    stdout_text = stdout_log.read_text() if stdout_log.exists() else ''
    stderr_text = stderr_log.read_text() if stderr_log.exists() else ''
    exit_label = 'OK' if proc.returncode == 0 else f'FAIL({proc.returncode})'
    print(f"  >> scan done: {exit_label}", file=sys.stderr, flush=True)

    # Locate session dir
    scan_dir = _find_scan_session_dir(output_dir)

    # Load all outputs
    scan_log = ''
    log_path = scan_dir / 'scan.log'
    if log_path.exists():
        scan_log = log_path.read_text()

    sbom = _load_json_or_gz(scan_dir / 'sbom.json')
    vulns = _load_json_or_gz(scan_dir / 'vulns.json')
    scan_manifest = _load_json_or_gz(scan_dir / 'raw' / 'scan-manifest.json')
    provenance = _load_json_or_gz(scan_dir / 'provenance.json')
    scan_plan = _load_json_or_gz(scan_dir / 'scan-plan.json')
    raw_files = _collect_raw_files(scan_dir / 'raw')
    libs_cloned = _list_cloned_libs(scan_dir / 'libs')

    # Find and query repo.db
    repo_db_path = _find_repo_db(output_dir, target_dir)
    db_data = _query_repo_db(repo_db_path) if repo_db_path else {}

    return ScanResult(
        exit_code=proc.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        output_dir=output_dir,
        scan_dir=scan_dir,
        repo_db_path=repo_db_path,
        scan_id=db_data.get('scan_id'),
        sbom=sbom,
        vulns=vulns,
        scan_log=scan_log,
        scan_manifest=scan_manifest,
        provenance=provenance,
        scan_plan=scan_plan,
        db_scan_row=db_data.get('scan_row'),
        db_findings=db_data.get('findings', []),
        db_ai_findings=db_data.get('ai_findings', []),
        db_dlp_findings=db_data.get('dlp_findings', []),
        db_unresolved=db_data.get('unresolved', []),
        db_sandbox_cache=db_data.get('sandbox_cache', []),
        libs_cloned=libs_cloned,
        raw_files=raw_files,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def reachctl_bin():
    """Locate reachctl binary or skip."""
    path = _find_reachctl()
    if not path:
        pytest.skip('reachctl not found (install reach-core or activate venv)')
    return path


@pytest.fixture(scope='session', autouse=True)
def install_test_registries():
    """Install registries-test.yaml → ~/.reachable/registries.yaml.
    Backs up existing config and restores on teardown."""
    backup = None
    if REGISTRIES_LIVE_PATH.exists():
        backup = REGISTRIES_LIVE_PATH.with_suffix('.yaml.bak')
        shutil.copy2(REGISTRIES_LIVE_PATH, backup)

    if REGISTRIES_TEST_YAML.exists():
        REGISTRIES_LIVE_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REGISTRIES_TEST_YAML, REGISTRIES_LIVE_PATH)

    yield

    # Restore original
    if backup and backup.exists():
        shutil.move(str(backup), str(REGISTRIES_LIVE_PATH))
    elif not backup and REGISTRIES_LIVE_PATH.exists():
        REGISTRIES_LIVE_PATH.unlink()


@pytest.fixture(scope='session')
def docker_services_up():
    """Check which Docker registry services are running.
    Returns a set of live service names. Skips only if NONE are up."""
    services = {
        'devpi':      f'{DEVPI_URL}/+api',
        'verdaccio':  f'{VERDACCIO_URL}/-/ping',
        'athens':     f'{ATHENS_URL}',
        'reposilite': f'{REPOSILITE_URL}',
    }
    live = {name for name, url in services.items() if _check_service(url)}
    if not live:
        pytest.skip('No Docker registry services running. '
                     'Run: cd private-registry && docker compose up -d --wait && ./setup.sh')
    return live


# --- Aggregate fixture: first available scan result ---

@pytest.fixture(scope='session')
def any_completed_scan(request, docker_services_up, reachctl_bin, tmp_path_factory):
    """Return the first scan result that completes successfully.
    Tries ecosystems in order based on which services are alive."""
    eco_map = {
        'verdaccio': ('npm-mixed',  {'NPM_CONFIG_USERCONFIG': ''}),
        'athens':    ('go-mixed',   {'GOPROXY': f'{ATHENS_URL},https://proxy.golang.org,direct',
                                     'GONOSUMCHECK': 'go.company.com/*', 'GONOSUMDB': 'go.company.com/*'}),
        'reposilite':('maven-mixed',{'MAVEN_SETTINGS': '', 'MAVEN_OPTS': ''}),
        'devpi':     ('python-mixed',{'PIP_CONFIG_FILE': '', 'PIP_TRUSTED_HOST': 'localhost'}),
    }
    for svc, (proj, env) in eco_map.items():
        if svc not in docker_services_up:
            continue
        target = TARGET_PROJECTS / proj
        if not target.exists():
            continue
        # Fix up env paths that need the target dir
        if proj == 'npm-mixed':
            env['NPM_CONFIG_USERCONFIG'] = str(target / '.npmrc')
        elif proj == 'maven-mixed':
            env['MAVEN_SETTINGS'] = str(target / 'settings.xml')
            env['MAVEN_OPTS'] = f'-Dmaven.repo.remote={REPOSILITE_URL}/releases'
        elif proj == 'python-mixed':
            env['PIP_CONFIG_FILE'] = str(target / 'pip.conf')
        tmp = tmp_path_factory.mktemp(f'any-{proj}')
        result = _run_reachctl_scan(reachctl_bin, target, tmp, extra_env=env)
        if result.exit_code == 0 and result.repo_db_path:
            return result
    pytest.skip('No ecosystem scan completed successfully')


# --- Per-ecosystem scan fixtures (session-scoped, run once) ---

@pytest.fixture(scope='session')
def python_mixed_scan(reachctl_bin, docker_services_up, tmp_path_factory):
    """Run reachctl scan on python-mixed target project."""
    if 'devpi' not in docker_services_up:
        pytest.skip('devpi not running (python registry)')
    target = TARGET_PROJECTS / 'python-mixed'
    if not target.exists():
        pytest.skip(f'Target project not found: {target}')
    # Warn if venv not present (deps won't be in SBOM)
    if not (target / '.venv').exists():
        import warnings
        warnings.warn('python-mixed/.venv missing — run run-private-registry-tests.sh first')
    tmp = tmp_path_factory.mktemp('python-scan')
    env = {
        'PIP_CONFIG_FILE': str(target / 'pip.conf'),
        'PIP_TRUSTED_HOST': 'localhost',
    }
    # If venv exists, put it on PATH so Syft finds installed packages
    venv_bin = target / '.venv' / 'bin'
    if venv_bin.exists():
        env['VIRTUAL_ENV'] = str(target / '.venv')
    return _run_reachctl_scan(reachctl_bin, target, tmp, extra_env=env)


@pytest.fixture(scope='session')
def npm_mixed_scan(reachctl_bin, docker_services_up, tmp_path_factory):
    """Run reachctl scan on npm-mixed target project."""
    if 'verdaccio' not in docker_services_up:
        pytest.skip('verdaccio not running (npm registry)')
    target = TARGET_PROJECTS / 'npm-mixed'
    if not target.exists():
        pytest.skip(f'Target project not found: {target}')
    if not (target / 'package-lock.json').exists():
        import warnings
        warnings.warn('npm-mixed/package-lock.json missing — run run-private-registry-tests.sh first')
    tmp = tmp_path_factory.mktemp('npm-scan')
    return _run_reachctl_scan(reachctl_bin, target, tmp, extra_env={
        'NPM_CONFIG_USERCONFIG': str(target / '.npmrc'),
    })


@pytest.fixture(scope='session')
def go_mixed_scan(reachctl_bin, docker_services_up, tmp_path_factory):
    """Run reachctl scan on go-mixed target project."""
    if 'athens' not in docker_services_up:
        pytest.skip('athens not running (go proxy)')
    target = TARGET_PROJECTS / 'go-mixed'
    if not target.exists():
        pytest.skip(f'Target project not found: {target}')
    if not (target / 'go.sum').exists():
        import warnings
        warnings.warn('go-mixed/go.sum missing — run run-private-registry-tests.sh first')
    tmp = tmp_path_factory.mktemp('go-scan')
    return _run_reachctl_scan(reachctl_bin, target, tmp, extra_env={
        'GOPROXY': f'{ATHENS_URL},https://proxy.golang.org,direct',
        'GONOSUMCHECK': 'go.company.com/*',
        'GONOSUMDB': 'go.company.com/*',
    })


@pytest.fixture(scope='session')
def maven_mixed_scan(reachctl_bin, docker_services_up, tmp_path_factory):
    """Run reachctl scan on maven-mixed target project."""
    if 'reposilite' not in docker_services_up:
        pytest.skip('reposilite not running (maven registry)')
    target = TARGET_PROJECTS / 'maven-mixed'
    if not target.exists():
        pytest.skip(f'Target project not found: {target}')
    tmp = tmp_path_factory.mktemp('maven-scan')
    return _run_reachctl_scan(reachctl_bin, target, tmp, extra_env={
        'MAVEN_SETTINGS': str(target / 'settings.xml'),
        'MAVEN_OPTS': f'-Dmaven.repo.remote={REPOSILITE_URL}/releases',
    })


# --- Negative test fixtures: scans WITHOUT private registry auth ---

@pytest.fixture(scope='session')
def npm_noauth_scan(reachctl_bin, docker_services_up, tmp_path_factory):
    """Run reachctl scan on npm-noauth (NO private registry auth).
    Public packages should resolve; @company/* should NOT."""
    if 'verdaccio' not in docker_services_up:
        pytest.skip('verdaccio not running — negative test requires it to prove auth matters')
    target = TARGET_PROJECTS / 'npm-noauth'
    if not target.exists():
        pytest.skip(f'Target project not found: {target}')
    tmp = tmp_path_factory.mktemp('npm-noauth-scan')
    # Deliberately uses .npmrc that does NOT point to Verdaccio
    return _run_reachctl_scan(reachctl_bin, target, tmp, extra_env={
        'NPM_CONFIG_USERCONFIG': str(target / '.npmrc'),
    })


@pytest.fixture(scope='session')
def python_noauth_scan(reachctl_bin, docker_services_up, tmp_path_factory):
    """Run reachctl scan on python-noauth (NO devpi auth).
    Public packages should resolve; internal-sdk should NOT."""
    if 'devpi' not in docker_services_up:
        pytest.skip('devpi not running — negative test requires it to prove auth matters')
    target = TARGET_PROJECTS / 'python-noauth'
    if not target.exists():
        pytest.skip(f'Target project not found: {target}')
    tmp = tmp_path_factory.mktemp('python-noauth-scan')
    env = {
        'PIP_CONFIG_FILE': str(target / 'pip.conf'),
    }
    venv_bin = target / '.venv' / 'bin'
    if venv_bin.exists():
        env['VIRTUAL_ENV'] = str(target / '.venv')
    return _run_reachctl_scan(reachctl_bin, target, tmp, extra_env=env)
