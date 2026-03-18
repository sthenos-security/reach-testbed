#!/usr/bin/env bash
# Copyright © 2026 Sthenos Security. All rights reserved.
# teardown.sh — Stop and remove private registry containers + volumes
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose down -v --remove-orphans
echo "Private registry infrastructure removed."
