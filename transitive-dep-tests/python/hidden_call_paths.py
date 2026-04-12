"""
Hidden Call Path Reachability Test Cases
========================================
INTENTIONALLY VULNERABLE — DO NOT USE IN PRODUCTION
Copyright © 2026 Sthenos Security. Test file only.

PURPOSE:
  Tests whether the scanner + Enzo (AI) can detect reachability through
  call paths that are INVISIBLE to static call graph analysis.

THE CORE PROBLEM:
  Static call graphs only trace calls within the project's own source files.
  They do NOT recurse into dependency source code (site-packages/, node_modules/).
  This means a call chain like:

    your_app.py → dep_a.do_thing() → dep_b.process() → dep_c.vulnerable_fn()
                  ^^^^^^^^^^^^^^^^
                  call graph STOPS HERE — cannot see inside dep_a's source

  The scanner sees:
    ✓ dep_a is imported in a reachable file
    ✓ dep_c has a CVE (from SBOM/Grype)
    ✓ dep_a → dep_b → dep_c dependency chain exists (from Syft SBOM)
    ✗ CANNOT verify dep_a internally calls dep_c's vulnerable function

WHAT ENZO GETS AS CONTEXT:
  1. dependency_chain: ["requests==2.28.0", "urllib3==1.26.0"] — knows the chain
  2. is_direct: 0 (transitive) or 1 (direct)
  3. Import sites: which files import the direct dep + whether they're reachable
  4. Call path: entrypoint → function that imports the direct dep
  5. Package health: deprecation, maintenance status
  6. EPSS/KEV: exploit likelihood data
  — BUT: no access to dep source code (site-packages/ etc.)

HOW ENZO REASONS (without reading dep source):
  Enzo uses training knowledge about well-known libraries:
  - "requests internally uses urllib3 for HTTP connections" — common knowledge
  - "boto3.client('s3').put_object() eventually calls urllib3" — known chain
  - "Flask's werkzeug handles request parsing" — training data

  For WELL-KNOWN packages, this works well. For obscure packages, Enzo can
  still reason probabilistically: "dep_a depends on dep_c, and the app calls
  dep_a's API — dep_c is likely exercised." But it cannot PROVE the path.

THE AI HINT PATTERN:
  When static analysis finds a dead-function-in-live-file, the scanner now
  classifies as UNKNOWN (not NOT_REACHABLE) with is_final=0, giving Enzo
  a chance to reason about indirect call paths. The reachability_reason
  includes "ai_hint:dead_fn_in_live_file" so Enzo knows to investigate.

  Without AI (--no-ai-reachability): stays UNKNOWN — honest "I don't know"
  With AI: Enzo evaluates and promotes to REACHABLE or confirms NOT_REACHABLE

TEST CASES BELOW:
  Each case demonstrates a specific hidden call path pattern that static
  analysis CANNOT trace. Comments explain what the scanner sees vs. reality.
"""

import requests
import boto3
from flask import Flask, request as flask_request

# =============================================================================
# PATTERN 1: Framework callback — hidden dispatch through framework internals
# =============================================================================
#
# WHAT HAPPENS AT RUNTIME:
#   Flask receives HTTP request → werkzeug parses it → Flask dispatches to
#   route handler → calls before_request hooks → your function runs
#
# WHAT STATIC ANALYSIS SEES:
#   register_hooks() is called → passes function references to Flask
#   But the CALL from Flask back to your function goes through werkzeug's
#   request dispatcher, which is in site-packages/ — call graph stops there.
#
# WHAT ENZO GETS:
#   - dep_chain: ["flask==2.2.0", "werkzeug==2.2.x"]
#   - import_site: this file, reachable (Flask app is created here)
#   - Enzo knows from training: Flask @app.before_request hooks ARE called
#     on every request — this is core Flask behavior
#
# STATIC VERDICT: UNKNOWN (function registered but no direct caller visible)
# AI VERDICT:     REACHABLE (Flask calls before_request hooks automatically)
# =============================================================================

app = Flask(__name__)


def audit_request_hook():
    """
    HIDDEN CALL PATH: This function has NO direct callers in the call graph.
    It's registered via @app.before_request — Flask calls it on every HTTP
    request through werkzeug's internal dispatch. Static analysis cannot trace
    Flask's internal request handling loop.

    Real-world example: audit logging, auth checks, request rate limiting.
    These are always reachable if the Flask app serves traffic.
    """
    remote_addr = flask_request.remote_addr
    user_agent = flask_request.headers.get("User-Agent", "unknown")
    print(f"[AUDIT] {remote_addr} - {user_agent}")  # nosec


def cleanup_on_teardown():
    """
    HIDDEN CALL PATH: Registered via @app.teardown_appcontext.
    Flask calls this after every request to clean up resources.
    No direct caller exists in the call graph.
    """
    print("[TEARDOWN] cleaning up request context")  # nosec


# These registrations are visible to static analysis, but the CALL BACK
# from Flask → your function goes through werkzeug internals (invisible).
app.before_request(audit_request_hook)
app.teardown_appcontext(cleanup_on_teardown)


@app.route("/api/hidden-path-test")
def hidden_path_entrypoint():
    """The visible entrypoint. audit_request_hook() runs BEFORE this."""
    return {"status": "ok"}


# =============================================================================
# PATTERN 2: Transitive dependency internal call — 3-hop chain
# =============================================================================
#
# ACTUAL CALL CHAIN AT RUNTIME (3 hops):
#   upload_with_retry()
#     → boto3.client("s3")           # hop 1: into boto3 (direct dep)
#       → botocore.session.Session   # hop 2: boto3 internally uses botocore
#         → urllib3.HTTPSPool        # hop 3: botocore uses urllib3 for HTTP
#           → urllib3 vulnerable code (CVE-2021-33503)
#
# WHAT STATIC ANALYSIS SEES:
#   upload_with_retry() → boto3.client()  ← STOPS HERE
#   Cannot trace: boto3 → botocore → urllib3
#
# WHAT ENZO GETS:
#   - dep_chain: ["boto3==1.26.0", "botocore==1.29.x", "urllib3==1.26.x"]
#   - The SBOM shows the full 3-hop chain
#   - Enzo knows: boto3.client("s3").put_object() ALWAYS uses urllib3
#     internally — this is how AWS SDK works, no alternative HTTP backend
#
# KEY INSIGHT: We DO have the dependency graph (from Syft SBOM). We just
# don't have the CALL graph through those dependencies. Enzo bridges
# this gap using training knowledge about how dependencies call each other.
#
# STATIC VERDICT: UNKNOWN (urllib3 is transitive, no call path visible)
# AI VERDICT:     REACHABLE (boto3 → botocore → urllib3 is guaranteed)
# =============================================================================


def upload_with_retry(bucket: str, key: str, data: bytes, retries: int = 3) -> bool:
    """
    3-HOP TRANSITIVE CHAIN:
    This function → boto3 → botocore → urllib3 (CVE-2021-33503).

    Static analysis sees: upload_with_retry() → boto3.client().put_object()
    Static analysis CANNOT see: boto3 internally creates a botocore session,
    which creates a urllib3 HTTPSPool to make the actual HTTPS request to AWS.

    The dependency tree (from SBOM) confirms:
      boto3==1.26.0 → botocore==1.29.x → urllib3==1.26.x

    But the CALL tree through those deps is invisible to our scanner.
    Enzo must reason: "boto3 S3 operations require HTTP → urllib3 is exercised."
    """
    client = boto3.client("s3")
    for attempt in range(retries):
        try:
            client.put_object(Bucket=bucket, Key=key, Body=data)
            return True
        except Exception:
            if attempt == retries - 1:
                raise
    return False


# =============================================================================
# PATTERN 3: Callback registration — dependency holds reference to your code
# =============================================================================
#
# WHAT HAPPENS AT RUNTIME:
#   requests.Session has hooks (event hooks). You can register a callback
#   that requests calls on every response. The call goes:
#   requests.get() → urllib3 → response created → hooks['response'] called
#   → YOUR function runs
#
# WHAT STATIC ANALYSIS SEES:
#   setup_session() registers the hook (visible)
#   But the CALL from requests back to log_response_hook() goes through
#   requests' internal Session.send() → hooks dispatch — invisible.
#
# WHAT ENZO GETS:
#   - import_site: this file, reachable
#   - dep_chain: ["requests==2.28.0"]
#   - Enzo knows: requests event hooks ARE called if the session is used
#
# STATIC VERDICT: UNKNOWN (registered but no direct caller)
# AI VERDICT:     REACHABLE (requests calls hooks on every response)
# =============================================================================

_session = requests.Session()


def log_response_hook(response, *args, **kwargs):
    """
    CALLBACK PATTERN: This function is registered as a requests response hook.
    requests internally calls it on every HTTP response via Session.send().

    No direct caller exists in the project source — the call comes from
    inside requests' source code (site-packages/requests/adapters.py).

    This is the pattern the user described: a "hidden function in an imported
    package or library" that calls back into your code. You can't see it
    in the call graph because the call originates inside the dependency.
    """
    print(f"[HOOK] {response.status_code} {response.url}")  # nosec
    return response


def log_slow_response_hook(response, *args, **kwargs):
    """
    CALLBACK PATTERN variant: Only logs slow responses.
    Same hidden call path — requests calls this, not the project code.
    """
    elapsed = response.elapsed.total_seconds()
    if elapsed > 1.0:
        print(f"[SLOW] {elapsed:.2f}s {response.url}")  # nosec
    return response


# Registration is visible; the callback invocation is not.
_session.hooks["response"].append(log_response_hook)
_session.hooks["response"].append(log_slow_response_hook)


def fetch_with_hooks(url: str) -> dict:
    """Uses the session with registered hooks — hooks fire on response."""
    response = _session.get(url, timeout=30)
    return response.json()


# =============================================================================
# PATTERN 4: Module-level initialization — runs on import
# =============================================================================
#
# WHAT HAPPENS AT RUNTIME:
#   When this module is imported, Python executes ALL module-level code.
#   The _configure_defaults() call below runs immediately on import.
#   If this file is imported by a reachable module, this code runs.
#
# WHAT STATIC ANALYSIS SEES:
#   _configure_defaults() has ONE caller: the module-level call below.
#   But it's a module-level call, not a function-level call from an entrypoint.
#   Whether it's "reachable" depends on whether this MODULE is imported —
#   which requires tracing import chains, not call chains.
#
# STATIC VERDICT: UNKNOWN (module-level call, import chain unclear)
# AI VERDICT:     REACHABLE (if any function in this file is called,
#                 the module was imported, and init code ran)
# =============================================================================


def _configure_defaults():
    """
    MODULE INIT PATTERN: This runs on import, not on explicit call.
    If ANY function in this file is reachable, this function also ran.

    Real-world examples:
    - Django's AppConfig.ready() runs on startup
    - Go's init() runs on package import
    - Python's module-level setup (DB connections, config loading)
    - Node.js module-level code (executed on require())
    """
    # This would typically set up logging, config, DB pools, etc.
    import logging
    logging.basicConfig(level=logging.INFO)
    return True


# This runs when the module is imported — invisible to function-level call graph
_initialized = _configure_defaults()


# =============================================================================
# PATTERN 5: Negative control — actually dead transitive chain
# =============================================================================
#
# This function is in a DEAD file (or never called from any entrypoint).
# Even though it calls deep transitive deps, it should be NOT_REACHABLE.
# Enzo should NOT promote this — no indirect path exists.
#
# STATIC VERDICT: NOT_REACHABLE (function never called, file may be dead)
# AI VERDICT:     NOT_REACHABLE (no framework hook, no callback, no init)
# =============================================================================


def dead_code_deep_transitive():
    """
    NEGATIVE CONTROL: This function is never called from any entrypoint.
    Even though it touches boto3 → botocore → urllib3 (3-hop chain),
    it should be NOT_REACHABLE because nothing invokes it.

    This proves the AI doesn't blindly promote everything with a transitive
    dep chain — it checks whether there's a plausible indirect call path.
    """
    client = boto3.client("dynamodb")
    client.scan(TableName="never_called")
    return "dead"


# =============================================================================
# SUMMARY: What the scanner can and cannot do
# =============================================================================
#
# CAN DO (static analysis):
#   ✓ Build full dependency tree from SBOM (all transitive deps, all hops)
#   ✓ Detect CVEs in any dep at any depth (via Grype against SBOM)
#   ✓ Trace call graph within project source files
#   ✓ Identify which files import which direct dependencies
#   ✓ Determine if import sites are reachable from entrypoints
#
# CANNOT DO (static analysis):
#   ✗ Trace calls INSIDE dependency source (site-packages, node_modules)
#   ✗ Prove dep_a internally calls dep_c's vulnerable function
#   ✗ Detect framework callbacks (dep calls YOUR code, not other way around)
#   ✗ Trace module-level init code through import chains
#   ✗ Resolve dynamic dispatch (reflection, getattr, interface dispatch)
#
# ENZO (AI) BRIDGES THE GAP:
#   When static analysis says UNKNOWN (dead-fn-in-live-file), Enzo gets:
#   - The dependency chain from SBOM
#   - The import sites and their reachability status
#   - The function signatures and surrounding code context
#   - Training knowledge about how well-known libraries work internally
#
#   Enzo reasons probabilistically:
#   - "requests always uses urllib3 internally" → REACHABLE
#   - "Flask @before_request hooks fire on every request" → REACHABLE
#   - "This function is never called and has no hook registration" → NOT_REACHABLE
#
#   LIMITATION: For obscure or custom packages, Enzo may not know the internal
#   call patterns. The dep_chain from SBOM helps, but Enzo cannot verify the
#   actual code path. This is an inherent limit of not parsing dep source.
#
# FUTURE IMPROVEMENT:
#   Selectively parsing high-value dependency source (top 100 packages per
#   ecosystem) would give the call graph actual cross-boundary edges.
#   For now, the AI hint pattern is a practical middle ground.
# =============================================================================
