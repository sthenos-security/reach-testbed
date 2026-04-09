# Fixture: CWE-22 Path Traversal - Python
# VERDICT: TRUE_POSITIVE
# PATTERN: rag_document_loader_unvalidated
# SOURCE: function_parameter
# SINK: open
# TAINT_HOPS: 1
# NOTES: RAG document loader - user provides filename, no path validation
# REAL_WORLD: llama_index document loader pattern
import os

def load_document(doc_name: str) -> str:
    doc_path = os.path.join("/data/documents", doc_name)
    # VULNERABLE: doc_name could be ../../etc/passwd
    with open(doc_path, "r") as f:
        return f.read()
