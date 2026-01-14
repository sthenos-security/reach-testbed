# CONFIG UNKNOWN REACHABILITY TEST
# =================================
# Dockerfile security issues - reachability is N/A for config files
# These represent deployment-time risks, not code execution paths

# Issue: Running as root (missing USER instruction)
# Severity: HIGH
# CWE: N/A (configuration issue)
FROM python:3.11-slim

# Issue: Using latest tag (unpinned version)
# Severity: MEDIUM
COPY requirements.txt .

RUN pip install -r requirements.txt

# Issue: Exposing debug port
# Severity: MEDIUM
EXPOSE 5000
EXPOSE 5001

COPY . /app
WORKDIR /app

# Missing: USER instruction - container runs as root
# Missing: HEALTHCHECK instruction
# Missing: Read-only filesystem

CMD ["python", "app.py"]
