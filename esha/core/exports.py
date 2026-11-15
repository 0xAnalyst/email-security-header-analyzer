"""Export a report: full JSON, IOCs as JSON or CSV, a STIX 2.1 bundle, a MISP
event, or a self-contained HTML report.

Everything works from the report dict, so the CLI, the API and the in-browser
engine produce identical files. No third-party libraries are needed.
"""
from __future__ import annotations

import csv
import html
import io
import json
import re
import uuid
from datetime import datetime, timezone

from .iocs import defang_url, extract

FORMATS = {
    "json": ("application/json", "report.json"),
    "iocs": ("application/json", "iocs.json"),
    "csv": ("text/csv", "iocs.csv"),
    "stix": ("application/stix+json;version=2.1", "stix-bundle.json"),
    "misp": ("application/json", "misp-event.json"),
    "html": ("text/html", "report.html"),
}

# STIX 2.1 namespace for deterministic cyber-observable IDs (section 2.9).
_STIX_SCO_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# ESHA's own namespace for the other objects, so re-exports produce the same IDs.
_ESHA_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/0xAnalyst/email-security-header-analyzer")


class ExportError(ValueError):
    pass


def export(report: dict, fmt: str) -> tuple[str, str, str]:
    """Return (content, media type, suggested file name)."""
    fmt = (fmt or "").lower()
    if fmt not in FORMATS:
        raise ExportError(f"Unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    if not isinstance(report, dict) or "summary" not in report:
        raise ExportError("Not an ESHA report")
    iocs = report.get("iocs") or extract(report)
    content = {
        "json": lambda: json.dumps(report, indent=2, default=str),
        "iocs": lambda: json.dumps(iocs, indent=2),
        "csv": lambda: to_csv(iocs),
        "stix": lambda: json.dumps(to_stix(report, iocs), indent=2),
        "misp": lambda: json.dumps(to_misp(report, iocs), indent=2),
        "html": lambda: to_html(report, iocs),
    }[fmt]()
    media, name = FORMATS[fmt]
    stamp = re.sub(r"[^0-9T]", "", ((report.get("meta") or {}).get("analyzed_at") or "")[:19])
    return content, media, f"esha-{stamp or 'report'}-{name}"


# ----------------------------------------------------------------- CSV
def _cell(value) -> str:
    """Neutralise spreadsheet formulas (CSV injection) in attacker-controlled values."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(iocs: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["type", "value", "defanged", "roles", "suspicious", "context"])
    for ip in iocs["ips"]:
        w.writerow(map(_cell, ["ip", ip["value"], ip["defanged"], ";".join(ip["roles"]), ip["suspicious"], ip.get("country") or ""]))
    for d in iocs["domains"]:
        w.writerow(map(_cell, ["domain", d["value"], d["defanged"], ";".join(d["roles"]), d["suspicious"], ""]))
    for u in iocs["urls"]:
        w.writerow(map(_cell, ["url", u["value"], u["defanged"], u["source"], u["suspicious"], "; ".join(u["flags"])]))
    for e in iocs["emails"]:
        w.writerow(map(_cell, ["email", e["value"], e["defanged"], ";".join(e["roles"]), "", ""]))
    for f in iocs["files"]:
        ctx = f"{f['content_type']}, {f['size']} bytes" + (f"; contains {', '.join(f['contains'][:10])}" if f["contains"] else "")
        w.writerow(map(_cell, ["sha256", f["sha256"], "", "attachment", f["suspicious"], f"{f['filename']} ({ctx})"]))
        w.writerow(map(_cell, ["md5", f["md5"], "", "attachment", f["suspicious"], f["filename"]]))
        w.writerow(map(_cell, ["filename", f["filename"], "", "attachment", f["suspicious"], ""]))
    m = iocs["message"]
    for key in ("subject", "message_id", "x_mailer"):
        if m.get(key):
            w.writerow(map(_cell, [f"email-{key.replace('_', '-')}", m[key], "", "message", "", ""]))
    return out.getvalue()


# ---------------------------------------------------------------- STIX
def _stix_time(report: dict) -> str:
    ts = (report.get("meta") or {}).get("analyzed_at")
    try:
        dt = datetime.fromisoformat(ts) if ts else datetime.now(timezone.utc)
    except ValueError:
        dt = datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sco_id(kind: str, props: dict) -> str:
    return f"{kind}--{uuid.uuid5(_STIX_SCO_NS, json.dumps(props, sort_keys=True, separators=(',', ':'), ensure_ascii=False))}"


def _pattern_value(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def to_stix(report: dict, iocs: dict) -> dict:
    ts = _stix_time(report)
    s = report.get("summary") or {}
    key = (s.get("message_id") or "") + "|" + ts
    identity = {"type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid5(_ESHA_NS, 'identity')}",
                "created": "2026-11-13T00:00:00.000Z", "modified": "2026-11-13T00:00:00.000Z",
                "name": "ESHA (Email Security Header Analyzer)", "identity_class": "system"}
    objects: list[dict] = [identity]
    indicators: list[dict] = []

    def sco(kind, props, extra=None):
        obj = {"type": kind, "spec_version": "2.1", "id": _sco_id(kind, props), **props, **(extra or {})}
        if not any(o["id"] == obj["id"] for o in objects):
            objects.append(obj)
        return obj["id"]

    def indicator(name, pattern, description):
        ind = {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(_ESHA_NS, pattern)}",
               "created_by_ref": identity["id"], "created": ts, "modified": ts, "name": name, "description": description,
               "indicator_types": ["malicious-activity"], "pattern": pattern, "pattern_type": "stix", "valid_from": ts}
        indicators.append(ind)

    for ip in iocs["ips"]:
        kind = "ipv6-addr" if ":" in ip["value"] else "ipv4-addr"
        sco(kind, {"value": ip["value"]})
        if ip["suspicious"]:
            indicator(f"Suspicious IP {ip['value']}", f"[{kind}:value = '{_pattern_value(ip['value'])}']",
                      f"Seen as {', '.join(ip['roles'])} in a message rated {report['score']['label'].lower()} by ESHA.")
    for d in iocs["domains"]:
        sco("domain-name", {"value": d["value"]})
        if d["suspicious"]:
            indicator(f"Suspicious domain {d['value']}", f"[domain-name:value = '{_pattern_value(d['value'])}']",
                      f"Seen as {', '.join(d['roles'])}.")
    for u in iocs["urls"]:
        sco("url", {"value": u["value"]})
        if u["suspicious"]:
            indicator(f"Suspicious URL on {u['host']}", f"[url:value = '{_pattern_value(u['value'])}']", "; ".join(u["flags"]))
    addr_ids = {}
    for e in iocs["emails"]:
        addr_ids[e["value"]] = sco("email-addr", {"value": e["value"]})
    for f in iocs["files"]:
        if not f.get("sha256"):
            continue
        hashes = {"SHA-256": f["sha256"], "MD5": f["md5"]}
        sco("file", {"hashes": hashes, "name": f["filename"]}, {"size": f["size"], "mime_type": f["content_type"]})
        if f["suspicious"]:
            indicator(f"Suspicious attachment {f['filename']}", f"[file:hashes.'SHA-256' = '{f['sha256']}']",
                      f"{f['filename']} ({f['content_type']}, {f['size']} bytes)")
    from_addr = ((s.get("from") or {}).get("address") or "").lower()
    msg = {"is_multipart": bool(report.get("content") and report["content"].get("attachments"))}
    if from_addr in addr_ids:
        msg["from_ref"] = addr_ids[from_addr]
    if s.get("subject"):
        msg["subject"] = s["subject"]
    if s.get("message_id"):
        msg["message_id"] = s["message_id"]
    msg_id = sco("email-message", {**msg}) if s.get("message_id") or s.get("subject") else None
    objects += indicators
    refs = [o["id"] for o in objects if o["type"] != "identity"]
    score = report["score"]
    objects.append({
        "type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(_ESHA_NS, key)}", "created_by_ref": identity["id"],
        "created": ts, "modified": ts, "published": ts, "name": f"ESHA analysis: {s.get('subject') or '(no subject)'}",
        "description": f"{score['label']} ({score['value']}/100). "
                       + "; ".join(f"{f['rule_id']} {f['title']}" for f in report.get("findings", [])
                                   if f["severity"] in ("critical", "high", "medium"))[:2000],
        "report_types": ["threat-report"], "object_refs": refs or [msg_id or identity["id"]],
        "labels": [f"esha-risk-{score['level']}"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(_ESHA_NS, 'bundle|' + key)}", "objects": objects}


# ---------------------------------------------------------------- MISP
def to_misp(report: dict, iocs: dict) -> dict:
    s = report.get("summary") or {}
    score = report["score"]
    ts = (report.get("meta") or {}).get("analyzed_at") or datetime.now(timezone.utc).isoformat()
    key = (s.get("message_id") or "") + "|" + ts
    attrs = []

    def attr(type_, category, value, comment="", to_ids=False):
        if value:
            attrs.append({"uuid": str(uuid.uuid5(_ESHA_NS, f"misp|{key}|{type_}|{value}")), "type": type_, "category": category,
                          "value": str(value), "comment": comment[:250], "to_ids": bool(to_ids), "distribution": "5"})

    for ip in iocs["ips"]:
        attr("ip-src" if "link" not in ip["roles"] else "ip-dst", "Network activity", ip["value"],
             ", ".join(ip["roles"]) + (f" ({ip['country']})" if ip.get("country") else ""), ip["suspicious"])
    for d in iocs["domains"]:
        attr("domain", "Network activity", d["value"], ", ".join(d["roles"]), d["suspicious"])
    for u in iocs["urls"]:
        attr("url", "Network activity", u["value"], "; ".join(u["flags"]) or u["source"], u["suspicious"])
    for e in iocs["emails"]:
        for role in e["roles"]:
            t = {"from": "email-src", "reply-to": "email-reply-to", "return-path": "email-src"}.get(role, "email")
            attr(t, "Payload delivery", e["value"], role)
    for f in iocs["files"]:
        if f.get("sha256"):
            attr("filename|sha256", "Payload delivery", f"{f['filename']}|{f['sha256']}", f["content_type"] or "", f["suspicious"])
            attr("filename|md5", "Payload delivery", f"{f['filename']}|{f['md5']}", f["content_type"] or "", f["suspicious"])
    attr("email-subject", "Payload delivery", s.get("subject"))
    attr("email-message-id", "Payload delivery", (s.get("message_id") or "").strip("<>"))
    attr("email-x-mailer", "Payload delivery", s.get("mailer"))
    level = {"high": "1", "medium": "2", "low": "3"}.get(score["level"], "4")
    return {"Event": {
        "uuid": str(uuid.uuid5(_ESHA_NS, "misp-event|" + key)), "info": f"ESHA: {s.get('subject') or '(no subject)'}"[:250],
        "date": ts[:10], "threat_level_id": level, "analysis": "1", "distribution": "0", "published": False,
        "Tag": [{"name": "tlp:amber"}, {"name": f"esha:risk=\"{score['level']}\""}],
        "Attribute": attrs,
    }}


# ---------------------------------------------------------------- HTML
_CSS = """
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1b2a4a;margin:0;background:#fff}
main{max-width:1000px;margin:0 auto;padding:28px 24px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px;border-bottom:2px solid #1b2a4a;padding-bottom:4px}
.meta{color:#4a5874;font-size:13px}.verdict{display:inline-block;font-weight:800;padding:6px 12px;border-radius:4px;margin:10px 0}
.high{background:#fbe6e7;color:#8e1420}.medium{background:#fff1d9;color:#7a4a00}.low,.none{background:#e1f2ea;color:#1f5c42}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-top:1px solid #d5dce5}
th{background:#eef1f4;font-weight:600}td.mono,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;overflow-wrap:anywhere}
.sev{font-weight:700;text-transform:uppercase;font-size:11.5px}.sev.critical,.sev.high{color:#c8323c}.sev.medium{color:#b26b00}
.sev.low{color:#2f5fa8}.sev.info,.sev.pass{color:#4a5874}.slow td{background:#fbe6e7}.slowest{color:#c8323c;font-weight:800}
.flag{color:#c8323c}.muted{color:#7a869c}.nowrap{white-space:nowrap;overflow-wrap:normal}.adv{color:#4a5874;font-size:12.5px}
@media print{main{padding:0}h2{page-break-after:avoid}tr{page-break-inside:avoid}}
"""


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _dur(sec) -> str:
    if sec is None:
        return ""
    sec = int(round(sec))
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60), ("s", 1)):
        if sec >= size or (unit == "s" and not parts):
            parts.append(f"{sec // size} {unit}")
            sec %= size
    return " ".join(parts[:2])


def _delivered(s: dict) -> str:
    if not s.get("delivered_utc"):
        return ""
    ds = s.get("delivery_seconds")
    if ds is None:
        return s["delivered_utc"]
    if ds >= 0:
        return f"{s['delivered_utc']} (delivered after {_dur(ds) if ds >= 1 else 'less than a second'})"
    return f"{s['delivered_utc']} ({_dur(-ds)} before the Date header: wrong sender clock or forged Date)"


def _table(headers, rows) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def to_html(report: dict, iocs: dict) -> str:
    """Self-contained report: inline CSS, no scripts, no external requests, every value escaped,
    URLs defanged so nothing in the file is clickable."""
    s = report.get("summary") or {}
    score = report["score"]
    a = report.get("auth") or {}
    meta = report.get("meta") or {}
    try:
        from esha import __version__ as version
    except Exception:  # pragma: no cover
        version = ""
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">
<title>ESHA report: {_e(s.get('subject') or '(no subject)')}</title><style>{_CSS}</style></head><body><main>
<p class="meta">Email Security Header Analyzer {_e(version)} · analyzed {_e(meta.get('analyzed_at'))} · links are defanged and nothing in this file loads or runs</p>
<h1>{_e(s.get('subject') or '(no subject)')}</h1>
<div class="verdict {_e(score['level'])}">{_e(score['label'])}: {_e(score['value'])}/100</div>"""]

    rows = [("From", (s.get("from") or {}).get("raw")), ("Reply-To", ", ".join(r.get("address", "") for r in s.get("reply_to") or [])),
            ("To", ", ".join(r.get("address", "") for r in s.get("to") or [])), ("Created", s.get("date_utc") or s.get("date")), ("Delivered", _delivered(s)),
            ("Message-ID", s.get("message_id")), ("Sent through", (s.get("esp") or {}).get("name"))]
    if report.get("origin"):
        o = report["origin"]
        rows.append(("Origin", f"{o.get('ip')} {((o.get('geo') or {}).get('country') or '')}".strip()))
    rows.append(("Authentication", f"SPF {a.get('spf', {}).get('result')}, DKIM {a.get('dkim', {}).get('result')}, "
                                   f"DMARC {a.get('dmarc', {}).get('result')}"))
    out.append(_table(["Field", "Value"], [f"<tr><th>{_e(k)}</th><td class=\"mono\">{_e(v)}</td></tr>" for k, v in rows if v]))

    out.append("<h2>Findings</h2>")
    out.append(_table(["Severity", "Rule", "Finding"], [
        f"<tr><td><span class=\"sev {_e(f['severity'])}\">{_e(f['severity'])}</span></td><td class=\"mono nowrap\">{_e(f.get('rule_id'))}</td>"
        f"<td><b>{_e(f['title'])}</b>" + (f"<br>{_e(f['detail'])}" if f.get("detail") else "")
        + (f"<div class=\"adv\">What to do: {_e(f['remediation'])}</div>" if f.get("remediation") and f["severity"] in
           ("critical", "high", "medium") else "") + "</td></tr>" for f in report.get("findings", [])]))

    hops = report.get("hops") or []
    delays = [h.get("delay") or 0 for h in hops[1:]]
    slowest = max(delays) if delays else 0
    out.append(f"<h2>Route</h2><p class=\"meta\">Total {_e(_dur((report.get('timing') or {}).get('total_seconds')))}; "
               "hops of 5 minutes or more are highlighted.</p>")
    hop_rows = []
    for i, h in enumerate(hops):
        d = h.get("delay")
        slow = i > 0 and (d or 0) >= 300
        mark = i > 0 and slowest > 0 and d == slowest
        hop_rows.append(f"<tr class=\"{'slow' if slow else ''}\"><td>{_e(h.get('hop'))}</td><td class=\"mono\">{_e(h.get('from'))}"
                        f"<br><span class=\"muted\">{_e(h.get('from_ip'))}</span></td><td class=\"mono\">{_e(h.get('by'))}</td>"
                        f"<td class=\"mono\">{_e(h.get('timestamp'))}</td><td class=\"{'slowest' if mark else ''}\">"
                        f"{'start' if i == 0 else _e('+' + _dur(d) if d is not None else '')}{' (slowest)' if mark else ''}</td>"
                        f"<td>{_e(h.get('with'))}</td></tr>")
    out.append(_table(["Hop", "From", "By", "Time (UTC)", "Delay", "With"], hop_rows) if hops else "<p>No Received headers.</p>")

    al = a.get("alignment") or []
    if len(al) > 1:
        out.append("<h2>Domain alignment</h2>")
        out.append(_table(["Identity", "Domain", "Matches From?", "Note"], [
            f"<tr><td>{_e(r['label'])}</td><td class=\"mono\">{_e(r['domain'])}</td>"
            f"<td>{'reference' if r.get('aligned') is None else ('yes' if r['aligned'] else ('look-alike' if r.get('lookalike') else 'no'))}</td>"
            f"<td>{_e(r.get('note'))}</td></tr>" for r in al]))

    c = report.get("content")
    if c:
        if c.get("attachments"):
            out.append("<h2>Attachments</h2>")
            out.append(_table(["File", "Type and size", "SHA-256", "Contains"], [
                f"<tr><td class=\"mono{' flag' if f['suspicious'] else ''}\">{_e(f['filename'])}</td>"
                f"<td>{_e(f['content_type'])}, {_e(f['size'])} B</td><td class=\"mono\">{_e(f['sha256'])}</td>"
                f"<td class=\"mono\">{_e(', '.join(f['contains'][:20]))}</td></tr>" for f in iocs["files"]]))
        if c.get("links"):
            out.append("<h2>Links</h2>")
            out.append(_table(["Host", "URL (defanged)", "Flags"], [
                f"<tr><td class=\"mono\">{_e(lk.get('host'))}</td><td class=\"mono\">{_e(defang_url(lk.get('href', '')))}</td>"
                f"<td class=\"flag\">{_e('; '.join(lk.get('flags') or []))}</td></tr>" for lk in c["links"][:300]]))

    out.append("<h2>Indicators</h2>")
    ioc_rows = []
    for ip in iocs["ips"]:
        ioc_rows.append(("IP", ip["defanged"], ", ".join(ip["roles"]), ip["suspicious"]))
    for d in iocs["domains"]:
        ioc_rows.append(("Domain", d["defanged"], ", ".join(d["roles"]), d["suspicious"]))
    for e in iocs["emails"]:
        ioc_rows.append(("Email", e["defanged"], ", ".join(e["roles"]), False))
    for u in iocs["urls"]:
        ioc_rows.append(("URL", u["defanged"], u["source"], u["suspicious"]))
    for f in iocs["files"]:
        ioc_rows.append(("SHA-256", f["sha256"], f["filename"], f["suspicious"]))
    out.append(_table(["Type", "Value (defanged)", "Role", "Suspicious"], [
        f"<tr><td>{_e(t)}</td><td class=\"mono\">{_e(v)}</td><td>{_e(r)}</td><td class=\"{'flag' if sus else 'muted'}\">"
        f"{'yes' if sus else 'no'}</td></tr>" for t, v, r, sus in ioc_rows]))

    out.append("<h2>All headers</h2>")
    out.append(_table(["Header", "Value"], [f"<tr><th class=\"mono\">{_e(h['name'])}</th><td class=\"mono\">{_e(h['value'])}</td></tr>"
                                            for h in report.get("headers", [])]))
    out.append("</main></body></html>\n")
    return "\n".join(out)
