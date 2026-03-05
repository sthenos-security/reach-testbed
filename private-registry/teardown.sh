#!/usr/bin/env bash
# teardown.sh — Stop and remove private registry containers + volumes
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose down -v --remove-orphans
echo "Private registry infrastructure removed."
