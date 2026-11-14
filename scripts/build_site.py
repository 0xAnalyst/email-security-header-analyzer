#!/usr/bin/env python3
"""Build ESHA as a static site (for GitHub Pages or any static host).

The static site runs the same Python analyzer (esha.core) in the visitor's
browser with Pyodide, so messages are never uploaded anywhere. Pyodide is
self-hosted next to the page; there are no CDN requests.

    pip install -r requirements.txt
    python scripts/build_site.py            # writes ./site
    python -m http.server -d site 8000      # preview at http://127.0.0.1:8000

The pure-Python dependencies are copied from the running environment, so the
browser build uses exactly the versions the server uses.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PYODIDE_VERSION = "0.29.5"
PYODIDE_URL = f"https://github.com/pyodide/pyodide/releases/download/{PYODIDE_VERSION}/pyodide-core-{PYODIDE_VERSION}.tar.bz2"
PYODIDE_SHA256 = "ab08aafc11a3c9a0fe73825eb2cec78bda9464348dd17414e7ec0132ef3451e8"
PYODIDE_FILES = ("pyodide.js", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json")

# Runtime dependencies of esha.core (geo uses maxminddb's pure-Python reader).
PY_DEPS = ("publicsuffixlist", "dateutil", "six", "tzdata", "maxminddb")
SKIP_SUFFIXES = (".so", ".pyd", ".dylib", ".pyc", ".pyi")


def fetch_pyodide(cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    tarball = cache / f"pyodide-core-{PYODIDE_VERSION}.tar.bz2"
    if not tarball.is_file():
        print(f"Downloading Pyodide {PYODIDE_VERSION} ...")
        with urllib.request.urlopen(PYODIDE_URL, timeout=120) as resp:
            tarball.write_bytes(resp.read())
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if digest != PYODIDE_SHA256:
        tarball.unlink()
        raise SystemExit(f"Pyodide checksum mismatch: got {digest}, expected {PYODIDE_SHA256}")
    return tarball


def install_pyodide(tarball: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:bz2") as tf:
        for member in tf.getmembers():
            name = Path(member.name).name
            if member.isfile() and name in PYODIDE_FILES:
                with tf.extractfile(member) as src:
                    (dest / name).write_bytes(src.read())
    missing = [f for f in PYODIDE_FILES if not (dest / f).is_file()]
    if missing:
        raise SystemExit(f"Pyodide archive is missing {missing}")


def _add_tree(zf: zipfile.ZipFile, src: Path, arc_root: str) -> None:
    for path in sorted(src.rglob("*")):
        if path.is_dir() or "__pycache__" in path.parts or path.suffix in SKIP_SUFFIXES:
            continue
        zf.write(path, f"{arc_root}/{path.relative_to(src).as_posix()}")


def build_bundle(dest: Path) -> None:
    """Zip esha.core, the GeoLite2 data and the pure-Python dependencies."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(ROOT / "esha" / "__init__.py", "esha/__init__.py")
        _add_tree(zf, ROOT / "esha" / "core", "esha/core")
        for mmdb in sorted((ROOT / "esha" / "static" / "data").glob("*.mmdb")):
            zf.write(mmdb, f"esha/static/data/{mmdb.name}")
        for name in PY_DEPS:
            mod = importlib.import_module(name)
            path = Path(mod.__file__)
            if path.name == "__init__.py":
                _add_tree(zf, path.parent, name)
            else:
                zf.write(path, path.name)


def render_index() -> str:
    from esha import __version__
    from esha.app import create_app

    app = create_app()
    with app.test_request_context("/"):
        from flask import render_template
        html = render_template("index.html", version=__version__, engine="browser")
    # The site may live under a sub-path (https://user.github.io/repo/), so use relative URLs.
    return html.replace('"/static/', '"static/').replace('href="/"', 'href="./"')


def build(out: Path, cache: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    static = out / "static"
    shutil.copytree(ROOT / "esha" / "static", static, ignore=shutil.ignore_patterns("data", "__pycache__", ".DS_Store"))
    install_pyodide(fetch_pyodide(cache), static / "pyodide")
    build_bundle(static / "py" / "esha-bundle.zip")
    (out / "index.html").write_text(render_index(), encoding="utf-8")
    (out / ".nojekyll").write_text("")  # serve files as-is
    total = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"Built {out} ({total / 1048576:.1f} MB)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=ROOT / "site")
    ap.add_argument("--cache", type=Path, default=ROOT / ".cache")
    args = ap.parse_args()
    build(args.out.resolve(), args.cache.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())

