"""Flask web application and JSON API."""
from __future__ import annotations

import os

from flask import Flask, Response, jsonify, render_template, request

from . import __version__
from .core import analyze
from .core.exports import FORMATS, ExportError, export
from .core.geo import database_info
from .core.inputs import MsgError, decode_bytes
from .core.scoring import get_config

MAX_UPLOAD = int(os.environ.get("ESHA_MAX_UPLOAD_MB", "10")) * 1024 * 1024


def create_app() -> Flask:
    get_config()  # fail at startup, not on the first request, if the scoring config is invalid
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
        """Accepts JSON {"headers": "..."}, form field ``headers``, a file upload named
        ``file`` (.eml, .msg, .txt), or a raw text/plain, message/rfc822 or
        application/vnd.ms-outlook body."""
        text, from_file, source = None, False, None
        upload = request.files.get("file")
        try:
            if upload and upload.filename:
                text, from_file, source = decode_bytes(upload.read(), upload.filename)
            elif request.mimetype in ("application/vnd.ms-outlook", "application/octet-stream"):
                text, from_file, source = decode_bytes(request.get_data(), "upload.msg")
        except MsgError as e:
            return jsonify(error=str(e)), 400
        if text is None:
            if request.is_json:
                text = (request.get_json(silent=True) or {}).get("headers")
            elif request.form.get("headers"):
                text = request.form["headers"]
            elif request.mimetype in ("text/plain", "message/rfc822"):
                text, from_file, source = decode_bytes(request.get_data(), rfc822=request.mimetype == "message/rfc822")
        if not text or not str(text).strip():
            return jsonify(error="No headers supplied. Paste headers or upload an .eml or .msg file."), 400
        report = analyze(str(text), from_file=from_file, source=source)
        fmt = request.args.get("format")
        if fmt and fmt != "json":
            return _file(report, fmt)
        return jsonify(report)

    def _file(report, fmt):
        try:
            content, media, name = export(report, fmt)
        except ExportError as e:
            return jsonify(error=str(e)), 400
        resp = Response(content, mimetype=media.split(";")[0])
        if ";" in media:
            resp.headers["Content-Type"] = media + "; charset=utf-8"
        resp.headers["Content-Disposition"] = f'attachment; filename="{name}"'
        return resp

    @app.post("/api/export")
    def api_export():
        """Convert a report (as returned by /api/analyze) to another format:
        {"report": {...}, "format": "csv|iocs|stix|misp|html|json"}."""
        body = request.get_json(silent=True) or {}
        if body.get("format") not in FORMATS:
            return jsonify(error=f"format must be one of {', '.join(FORMATS)}"), 400
        return _file(body.get("report"), body["format"])

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
