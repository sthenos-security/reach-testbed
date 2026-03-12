# Copyright © 2026 Sthenos Security. All rights reserved.
"""
Signal Matrix — Python entrypoint
==================================
Imports ONLY the REACHABLE and UNKNOWN modules.
NOT_REACHABLE modules are never imported here — that's what makes them NOT_REACHABLE.

UNKNOWN pattern: module IS imported (so it's on the import graph) but only
safe/non-vulnerable functions from it are called. The vulnerable function
exists in the module but is never on a traced call path from any entrypoint.
"""

from flask import Flask, request, jsonify

# REACHABLE imports — vulnerable functions ARE called below
from signals.cve_reachable    import fetch_user_data
from signals.cwe_reachable    import render_template_unsafe, execute_query
from signals.secret_reachable import get_payment_token
from signals.dlp_reachable    import process_patient_record
from signals.ai_reachable     import run_llm_query
from signals.malware_reachable import initialize_app

# UNKNOWN imports — module is imported but only the SAFE function is called
# The VULNERABLE function exists in each module but is never invoked here
from signals.cwe_unknown    import safe_render        # NOT: unsafe_render_unknown()
from signals.secret_unknown import get_public_config  # NOT: get_internal_secret_unknown()
from signals.dlp_unknown    import get_public_profile # NOT: export_pii_unknown()
from signals.ai_unknown     import get_model_info     # NOT: run_unchecked_llm_unknown()

# NOT_REACHABLE modules are NEVER imported — they don't appear here at all:
#   signals/cve_not_reachable.py     ← never imported
#   signals/cwe_not_reachable.py     ← never imported
#   signals/secret_not_reachable.py  ← never imported
#   signals/dlp_not_reachable.py     ← never imported
#   signals/ai_not_reachable.py      ← never imported
#   signals/malware_not_reachable.py ← never imported

app = Flask(__name__)


@app.route("/api/user/<int:uid>")
def user_endpoint(uid):
    data = fetch_user_data(uid)
    profile = get_public_profile(uid)       # UNKNOWN: safe function from dlp_unknown
    config  = get_public_config()           # UNKNOWN: safe function from secret_unknown
    return jsonify({"data": data, "profile": profile, "config": config})


@app.route("/api/render", methods=["POST"])
def render_endpoint():
    html = render_template_unsafe(request.json.get("tmpl", ""))  # REACHABLE CWE
    safe = safe_render(request.json.get("safe", ""))             # UNKNOWN: safe func
    return jsonify({"html": html, "safe": safe})


@app.route("/api/query", methods=["POST"])
def query_endpoint():
    return jsonify({"rows": execute_query(request.json.get("q", ""))})  # REACHABLE CWE


@app.route("/api/pay", methods=["POST"])
def payment_endpoint():
    token = get_payment_token()  # REACHABLE SECRET
    return jsonify({"token": token[:4] + "****"})


@app.route("/api/patient", methods=["POST"])
def patient_endpoint():
    return jsonify(process_patient_record(request.json))  # REACHABLE DLP


@app.route("/api/llm", methods=["POST"])
def llm_endpoint():
    result = run_llm_query(request.json.get("prompt", ""))  # REACHABLE AI
    info   = get_model_info()                               # UNKNOWN: safe func
    return jsonify({"result": result, "model": info})


if __name__ == "__main__":
    initialize_app()  # REACHABLE MALWARE
    app.run(debug=True)
