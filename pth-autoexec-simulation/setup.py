"""
Minimal setup.py for the .pth auto-execution test package.
This setup.py is intentionally clean — the attack vector is the .pth file,
not the install hook.
"""

from setuptools import setup, find_packages

setup(
    name="fake-proxy-test",
    version="0.0.1",
    description="SECURITY TEST — .pth auto-execution simulation",
    py_modules=["metadata_service_sim"],
    data_files=[
        (".", ["autorun_init.pth"]),
    ],
    python_requires=">=3.8",
)
