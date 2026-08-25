#!/usr/bin/env sh
set -eu
: "${PORT:=5000}"
exec python3 -m uvicorn app:app --host 0.0.0.0 --port "$PORT" --proxy-headers
