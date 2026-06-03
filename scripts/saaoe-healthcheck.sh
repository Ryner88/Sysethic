#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SAAOE_BASE_URL:-http://127.0.0.1:5000}"

printf 'Checking %s/health\n' "$BASE_URL"
curl -fsS "$BASE_URL/health" >/dev/null
printf 'SAAOE health endpoint is reachable.\n'

printf 'Checking protected telemetry access control\n'
status="$(curl -fsS -o /dev/null -w '%{http_code}' "$BASE_URL/api/usage" || true)"
if [ "$status" != "401" ] && [ "$status" != "503" ]; then
  printf 'Expected /api/usage to require authentication or first-run setup, got HTTP %s\n' "$status" >&2
  exit 1
fi
printf 'Protected telemetry returned HTTP %s as expected.\n' "$status"
