# Fixture: code_patch · CWE-22 Path Traversal · Python
# VERDICT: TRUE_POSITIVE
# PATTERN: user_dataset_id_in_path
# SOURCE: function_parameter
# SINK: open
# TAINT_HOPS: 1
# NOTES: Dataset ID directly in path — traversal + potential deser
import os, pickle

def load_dataset_cache(dataset_id):
    # VULNERABLE: dataset_id unvalidated in path
    cache_path = os.path.join('/home/datasets', dataset_id, 'cache.pkl')
    return open(cache_path, 'rb')
