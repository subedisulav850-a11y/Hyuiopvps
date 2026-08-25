#!/usr/bin/env sh
set -eu
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || { echo "Python 3 is required" >&2; exit 1; }
"$PYTHON" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install --requirement requirements.txt
if [ ! -f .env ]; then cp .env.example .env; fi
printf '%s\n' 'Installed. Set values in .env, then run: . .venv/bin/activate && ./run.sh'
