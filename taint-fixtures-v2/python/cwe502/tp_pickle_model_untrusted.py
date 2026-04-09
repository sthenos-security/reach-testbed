# Fixture: CWE-502 Deserialization - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: pickle_load_user_uploaded_model
# SOURCE: http_upload
# SINK: pickle.load
# TAINT_HOPS: 1
# NOTES: ML serving pattern - user uploads model file, server pickle.loads it
# REAL_WORLD: common pattern in model registries and serving APIs
import pickle
from flask import request

def upload_model():
    model_file = request.files['model']
    # VULNERABLE: pickle from untrusted upload - RCE
    model = pickle.load(model_file)
    return {"status": "loaded"}
