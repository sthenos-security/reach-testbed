# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: zipfile_extractall_no_validation
# SOURCE: file_upload (zip archive)
# SINK: ZipFile.extractall (no path check)
# TAINT_HOPS: 1
import zipfile
from flask import request


def upload_and_extract():
    uploaded = request.files["archive"]
    zip_path = "/tmp/upload.zip"
    uploaded.save(zip_path)
    # VULNERABLE: CWE-22 · extractall without member validation
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall("/var/data/uploads")
