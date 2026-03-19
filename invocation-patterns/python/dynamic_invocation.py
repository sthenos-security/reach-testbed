"""
Dynamic Invocation Test Cases — Python
=======================================
Tests patterns where static CG misses function reachability.

Each function is annotated with:
  REACH: expected reachability state
  CG:    whether static CG catches it (YES/NO/PARTIAL)
  WHY:   root cause if static CG misses

Entry point for all REACHABLE cases: this file is called from app.py
"""
import threading
import signal
import importlib
import os
from concurrent.futures import ThreadPoolExecutor

# ─────────────────────────────────────────────────────────────────
# CASE 1: threading.Thread(target=fn)
# REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
# ─────────────────────────────────────────────────────────────────

def thread_worker_reachable():
    """
    CWE-78: OS command injection via thread target.
    Called via threading.Thread(target=thread_worker_reachable) — solvable by AST.
    """
    cmd = os.environ.get("CMD", "ls")
    os.system(cmd)  # CWE-78 REACHABLE: env var taint → OS command


def launch_worker():
    """Entry point: starts the thread."""
    t = threading.Thread(target=thread_worker_reachable, daemon=True)
    t.start()
    return t


# ─────────────────────────────────────────────────────────────────
# CASE 2: signal.signal(SIG, handler)
# REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
# ─────────────────────────────────────────────────────────────────

def sigterm_handler_reachable(sig, frame):
    """
    CWE-78: unsafe cleanup via signal handler.
    Registered via signal.signal(SIGTERM, ...) — solvable by AST.
    """
    cleanup_path = os.environ.get("CLEANUP_PATH", "/tmp/cleanup.sh")
    os.system(f"bash {cleanup_path}")  # CWE-78 REACHABLE


signal.signal(signal.SIGTERM, sigterm_handler_reachable)


# ─────────────────────────────────────────────────────────────────
# CASE 3: ThreadPoolExecutor.submit(fn)
# REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
# ─────────────────────────────────────────────────────────────────

def executor_task_reachable(user_input: str):
    """
    CWE-78: OS command via executor submit.
    Called via executor.submit(executor_task_reachable, ...) — solvable by AST.
    """
    os.system(f"process {user_input}")  # CWE-78 REACHABLE: param taint


def run_with_executor(user_input: str):
    with ThreadPoolExecutor(max_workers=2) as executor:
        future = executor.submit(executor_task_reachable, user_input)
        return future.result()


# ─────────────────────────────────────────────────────────────────
# CASE 4: dict dispatch table
# REACH: REACHABLE   CG: PARTIAL   CONFIDENCE: MEDIUM
# Static CG misses: which handler is called depends on runtime key
# ─────────────────────────────────────────────────────────────────

def dispatch_create_reachable(data: dict):
    """
    CWE-89: SQL injection via dict dispatch.
    Stored in DISPATCH_TABLE as a value — CG should see dict literals.
    """
    name = data.get("name", "")
    query = f"INSERT INTO users (name) VALUES ('{name}')"  # CWE-89 REACHABLE
    return query


def dispatch_delete_reachable(data: dict):
    """CWE-89: SQL injection via dict dispatch."""
    uid = data.get("id", "")
    query = f"DELETE FROM users WHERE id={uid}"  # CWE-89 REACHABLE
    return query


DISPATCH_TABLE = {
    "create": dispatch_create_reachable,
    "delete": dispatch_delete_reachable,
}


def handle_dispatch(action: str, data: dict):
    handler = DISPATCH_TABLE.get(action)
    if handler:
        return handler(data)


# ─────────────────────────────────────────────────────────────────
# CASE 5: map(fn, iterable)
# REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: MEDIUM
# ─────────────────────────────────────────────────────────────────

def process_item_reachable(item: str) -> str:
    """
    CWE-78: OS command per-item via map().
    Called via map(process_item_reachable, items).
    """
    os.system(f"log-item {item}")  # CWE-78 REACHABLE
    return item.upper()


def process_all(items: list) -> list:
    return list(map(process_item_reachable, items))


# ─────────────────────────────────────────────────────────────────
# CASE 6: getattr() dynamic dispatch
# REACH: UNKNOWN    CG: NO    CONFIDENCE: LOW
# Cannot determine which function is called without runtime knowledge
# ─────────────────────────────────────────────────────────────────

def action_read():
    """CWE-22: path traversal. Reachable only if caller passes 'read'."""
    path = os.environ.get("FILE_PATH", "/etc/passwd")
    with open(path) as f:  # CWE-22 UNKNOWN: dynamic dispatch
        return f.read()


def action_write():
    """CWE-22: path traversal via write."""
    path = os.environ.get("FILE_PATH", "/tmp/out")
    with open(path, "w") as f:  # CWE-22 UNKNOWN
        f.write("data")


def dynamic_dispatch_unknown(action_name: str):
    """
    CG cannot determine which action_* function is called.
    Mark all action_* as UNKNOWN (not NOT_REACHABLE).
    """
    import sys
    fn = getattr(sys.modules[__name__], f"action_{action_name}", None)
    if fn:
        return fn()


# ─────────────────────────────────────────────────────────────────
# CASE 7: eval() / exec() with tainted input
# REACH: REACHABLE   CG: PARTIAL (sees eval call, not callee)
# CONFIDENCE: HIGH for the eval call itself; callee is UNKNOWN
# ─────────────────────────────────────────────────────────────────

def eval_user_code_reachable(user_expression: str):
    """
    CWE-94: Code injection via eval().
    The eval() call IS reachable; what it runs is UNKNOWN at static time.
    Taint: user_expression → eval() → arbitrary code execution.
    """
    result = eval(user_expression)  # CWE-94 REACHABLE: param taint → eval
    return result


# ─────────────────────────────────────────────────────────────────
# CASE 8: importlib.import_module with variable
# REACH: UNKNOWN    CG: NO    CONFIDENCE: LOW
# Cannot determine module without runtime value of plugin_name
# ─────────────────────────────────────────────────────────────────

def load_plugin_unknown(plugin_name: str):
    """
    Dynamic import — module name determined at runtime.
    Mark as UNKNOWN: the loaded module may contain dangerous code.
    """
    try:
        mod = importlib.import_module(f"plugins.{plugin_name}")
        return mod.run()  # CWE-829 UNKNOWN: uncontrolled resource load
    except ImportError:
        return None


# ─────────────────────────────────────────────────────────────────
# CASE 9: Dead code — never invoked by any of the above
# REACH: NOT_REACHABLE   CG: YES
# ─────────────────────────────────────────────────────────────────

def dead_dynamic_handler():
    """
    This function exists but no dynamic registration points to it.
    Expected: NOT_REACHABLE.
    """
    os.system("rm -rf /tmp/dead")  # CWE-78 NOT_REACHABLE
