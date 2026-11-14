"""Flask web application and JSON API."""
from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from . import __version__
from .core import analyze
from .core.geo import database_info

MAX_UPLOAD = int(os.environ.get("MHA_MAX_UPLOAD_MB", "10")) * 1024 * 1024


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
    app.json.sort_keys = False

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "interest-cohort=()")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/")
    def index():
        return render_template("index.html", version=__version__)

    @app.post("/api/analyze")
    def api_analyze():
        """Accepts JSON {"headers": "..."}, form field ``headers``, a file
        upload named ``file`` (.eml/.txt), or a raw text/plain or message/rfc822 body."""
        text, from_file = None, False
        upload = request.files.get("file")
        if upload and upload.filename:
            text = _decode(upload.read())
            from_file = upload.filename.lower().endswith((".eml", ".mbox"))
        elif request.is_json:
            body = request.get_json(silent=True) or {}
            text = body.get("headers")
        elif request.form.get("headers"):
            text = request.form["headers"]
        elif request.mimetype in ("text/plain", "message/rfc822"):
            text, from_file = _decode(request.get_data()), request.mimetype == "message/rfc822"
        if not text or not str(text).strip():
            return jsonify(error="No headers supplied. Paste headers or upload an .eml file."), 400
        return jsonify(analyze(str(text), from_file=from_file))

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=__version__, geoip=database_info())

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error=f"File too large (limit {MAX_UPLOAD // 1024 // 1024} MB)."), 413

    # Backwards compatibility with the original form POST to "/".
    @app.post("/")
    def legacy_post():
        return render_template("index.html", version=__version__, prefill=request.form.get("headers", ""))

    return app


app = create_app()
