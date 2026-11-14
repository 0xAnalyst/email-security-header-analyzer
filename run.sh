#!/usr/bin/env sh
# One-step local launcher for macOS / Linux.
set -e
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python 3.9+ is required: https://www.python.org/downloads/"; exit 1; }
if [ ! -d .venv ]; then
  echo "Creating virtual environment..."
  "$PY" -m venv .venv
fi
. .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt
python -m mha --open "$@"
