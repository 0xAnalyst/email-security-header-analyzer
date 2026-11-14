#!/usr/bin/env sh
# One-step local launcher for macOS / Linux.
cd "$(dirname "$0")" || exit 1

fail() { echo; echo "ESHA could not start: $1"; exit 1; }

# Pick the newest Python 3.9+ available (Homebrew, pyenv, python.org, system).
PY=""
for cand in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    PY=$(command -v "$cand"); break
  fi
done
[ -z "$PY" ] && fail "Python 3.9 or newer is required. Install it from https://www.python.org/downloads/ or run: brew install python"
echo "Using $("$PY" --version 2>&1) at $PY"

# (Re)create the virtual environment if it is missing or broken.
if [ ! -x .venv/bin/python ] || ! .venv/bin/python -c 'import sys' >/dev/null 2>&1; then
  echo "Creating virtual environment..."
  rm -rf .venv
  "$PY" -m venv .venv || fail "could not create a virtual environment with $PY"
fi

if [ ! -f .venv/.deps-ok ] || [ requirements.txt -nt .venv/.deps-ok ]; then
  echo "Installing dependencies (first run only, needs internet)..."
  .venv/bin/python -m pip install -q --upgrade pip >/dev/null 2>&1
  .venv/bin/python -m pip install -q -r requirements.txt || fail "dependency install failed (check your internet connection or proxy settings)"
  touch .venv/.deps-ok
fi

exec .venv/bin/python -m esha --open "$@"
