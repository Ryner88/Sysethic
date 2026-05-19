#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SAAOE_BASE_URL:-http://127.0.0.1:5000}"

printf 'Checking %s/health\n' "$BASE_URL"
curl -fsS "$BASE_URL/health" >/dev/null
printf 'SAAOE health endpoint is reachable.\n'
