"""Parsing of authentication-related headers (SPF, DKIM, DMARC, ARC) and
vendor spam-filter verdicts."""
from __future__ import annotations

import re


def strip_comments(text: str) -> str:
    out, depth = [], 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def split_top(text: str, sep: str = ";") -> list[str]:
    """Split on ``sep`` outside parentheses and quotes."""
    parts, buf, depth, quoted = [], [], 0, False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0 and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


_COMMENT_RE = re.compile(r"\(([^()]*)\)")


def parse_authentication_results(value: str) -> dict:
    """RFC 8601 Authentication-Results parser.

    Returns {"authserv_id": str, "results": [{"method", "result", "reason",
    "props": {...}, "comment"}]}
    """
    value = " ".join(value.split())
    parts = split_top(value)
    out = {"authserv_id": "", "results": [], "raw": value}
    if not parts:
        return out
    first = strip_comments(parts[0]).strip()
    rest = parts[1:]
    # The authserv-id segment has no "=" (except optional version number).
    if "=" in first and re.match(r"^\s*[\w.-]+\s*=", first):
        rest = parts  # no authserv-id present
    else:
        out["authserv_id"] = first.split()[0] if first.split() else ""
    for part in rest:
        comments = " ".join(c.strip() for c in _COMMENT_RE.findall(part))
        clean = strip_comments(part).strip()
        if clean.lower() == "none":
            continue
        # One segment can contain several "method=result" pairs if a sender
        # forgot the ';'. Split on each method token.
        tokens = re.findall(r'([\w.-]+)\s*=\s*("[^"]*"|[^\s;]+)', clean)
        if not tokens:
            continue
        method, result = tokens[0]
        entry = {
            "method": method.lower(),
            "result": result.strip('"').lower(),
            "reason": "",
            "props": {},
            "comment": comments,
        }
        for key, val in tokens[1:]:
            val = val.strip('"')
            if key.lower() == "reason":
                entry["reason"] = val
            elif "." in key:
                entry["props"][key.lower()] = val
            else:
                # e.g. "dmarc=pass ... compauth=pass" — a new method inline
                out["results"].append(entry)
                entry = {"method": key.lower(), "result": val.lower(), "reason": "", "props": {}, "comment": ""}
        if entry["method"] == "dmarc" and comments:
            for k, v in re.findall(r"\b(p|sp|dis|pct)=(\w+)", comments, re.IGNORECASE):
                entry["props"]["policy." + k.lower()] = v
        out["results"].append(entry)
    return out


def parse_arc_authentication_results(value: str) -> dict:
    m = re.match(r"\s*i\s*=\s*(\d+)\s*;(.*)$", " ".join(value.split()))
    if not m:
        return {"instance": None, **parse_authentication_results(value)}
    return {"instance": int(m.group(1)), **parse_authentication_results(m.group(2))}


def parse_tag_list(value: str) -> dict:
    """DKIM-style ``k=v; k2=v2`` tag list."""
    tags = {}
    for part in " ".join(value.split()).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def parse_dkim_signature(value: str) -> dict:
    tags = parse_tag_list(value)
    signed = [h.strip().lower() for h in tags.get("h", "").replace(" ", "").split(":") if h.strip()]
    return {
        "domain": tags.get("d", "").lower(),
        "selector": tags.get("s", ""),
        "algorithm": tags.get("a", ""),
        "identity": tags.get("i", ""),
        "canonicalization": tags.get("c", ""),
        "signed_headers": signed,
        "timestamp": tags.get("t"),
        "expires": tags.get("x"),
        "body_length": tags.get("l"),
    }


def parse_received_spf(value: str) -> dict:
    value = " ".join(value.split())
    m = re.match(r"\s*(\w+)", value)
    result = m.group(1).lower() if m else ""
    comment = " ".join(_COMMENT_RE.findall(value))
    tags = {}
    for k, v in re.findall(r"\b([\w-]+)=(\"[^\"]*\"|[^\s;]+)", strip_comments(value)):
        tags[k.lower()] = v.strip('"')
    return {"result": result, "comment": comment, "tags": tags, "raw": value}


def parse_ms_antispam(headers: dict[str, list[str]]) -> dict:
    """Microsoft 365 / Exchange Online Protection verdicts."""
    out = {}
    report = " ".join(headers.get("x-forefront-antispam-report", []))
    if report:
        tags = {}
        for part in report.split(";"):
            if ":" in part:
                k, v = part.split(":", 1)
                tags[k.strip().upper()] = v.strip()
        for key in ("SCL", "SFV", "CAT", "IPV", "SRV", "CIP", "CTRY", "LANG", "PTR", "SFTY"):
            if tags.get(key):
                out[key] = tags[key]
    for name in ("x-ms-exchange-organization-scl",):
        if headers.get(name) and "SCL" not in out:
            out["SCL"] = headers[name][0].strip()
    antispam = " ".join(headers.get("x-microsoft-antispam", []))
    m = re.search(r"BCL:(\d+)", antispam)
    if m:
        out["BCL"] = m.group(1)
    return out


def parse_spam_status(headers: dict[str, list[str]]) -> dict:
    """SpamAssassin / rspamd style verdicts."""
    out = {}
    status = " ".join(headers.get("x-spam-status", []))
    if status:
        m = re.match(r"\s*(\w+)", status)
        out["flagged"] = bool(m and m.group(1).lower() == "yes")
        sm = re.search(r"(?:score|hits)=(-?[\d.]+)", status)
        rm = re.search(r"required=(-?[\d.]+)", status)
        tm = re.search(r"tests=([^\s]+(?:,\s*[^\s,]+)*)", status)
        if sm:
            out["score"] = float(sm.group(1))
        if rm:
            out["required"] = float(rm.group(1))
        if tm:
            out["tests"] = [t.strip() for t in tm.group(1).split(",") if t.strip()]
    if headers.get("x-spam-score") and "score" not in out:
        try:
            out["score"] = float(headers["x-spam-score"][0].split()[0])
        except (ValueError, IndexError):
            pass
    if headers.get("x-spam-flag"):
        out["flagged"] = headers["x-spam-flag"][0].strip().upper() == "YES"
    return out
