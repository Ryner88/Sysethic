#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit SAAOE_SECRET_KEY before operational use."
fi

exec venv/bin/python web/saaoe_api.py
