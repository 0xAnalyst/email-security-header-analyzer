"""Backwards-compatible entry point: ``python mha/server.py -b 0.0.0.0 -p 8080``
and ``gunicorn --chdir mha server:app`` still work."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mha.app import app  # noqa: F401

if __name__ == "__main__":
    from mha.__main__ import main

    sys.exit(main(["serve", *sys.argv[1:]]) or 0)
