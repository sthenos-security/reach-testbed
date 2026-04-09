# Fixture: code_patch · CWE-78 Command Injection · Python
# VERDICT: TRUE_NEGATIVE
# PATTERN: subprocess_env_dict_separate
# SOURCE: environment_variables
# SINK: subprocess.run
# TAINT_HOPS: 0
# NOTES: TensorFlow-style — env vars passed as dict, not interpolated into cmd
# REAL_WORLD: tensorflow/tensorflow configure.py
import subprocess, os

def build_tensorflow():
    environ_cp = dict(os.environ)
    environ_cp['PYTHON_BIN_PATH'] = '/usr/bin/python3'
    environ_cp['TF_NEED_CUDA'] = '1'
    # SAFE: list form + env passed separately
    return subprocess.run(['bazel', 'build', '//tensorflow/...'],
                          env=environ_cp, shell=False)
