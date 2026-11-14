"""Parsing of ``Received:`` headers into an ordered list of relay hops."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import dateutil.parser

KEYWORDS = ("from", "by", "via", "with", "id", "for")

_IPV4 = r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"
_IPV4_RE = re.compile(_IPV4)
# Loose IPv6 candidate matcher; every candidate is validated with ``ipaddress``.
_IPV6_RE = re.compile(r"(?<![\w:.])(?:IPv6:)?([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?::" + _IPV4 + r")?)(?![\w:])")
_TZ_NAME_RE = re.compile(r"\(\s*[A-Za-z]{2,5}\s*\)\s*$")


def _parse_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def find_ips(text: str) -> list[str]:
    """Return every valid IPv4/IPv6 literal found in ``text`` (in order, de-duplicated)."""
    found: list[str] = []
    for m in _IPV4_RE.finditer(text):
        if m.group(0) not in found:
            found.append(m.group(0))
    for m in _IPV6_RE.finditer(text):
        cand = m.group(1)
        if cand.count(":") < 2:
            continue
        ip = _parse_ip(cand)
        if ip is not None and ip.version == 6:
            s = str(ip)
            if s not in found:
                found.append(s)
    return found


def is_public_ip(ip: str) -> bool:
    obj = _parse_ip(ip)
    return bool(obj and obj.is_global and not obj.is_multicast)


def parse_date(text: str) -> tuple[datetime | None, bool]:
    """Parse a mail date. Returns (aware datetime in UTC, had_explicit_timezone)."""
    if not text:
        return None, False
    text = " ".join(text.split())
    cleaned = _TZ_NAME_RE.sub("", text).strip()
    dt = None
    try:
        dt = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is None:
        for candidate in (cleaned, re.split(r"\(|\butc\b", cleaned, flags=re.IGNORECASE)[0]):
            try:
                dt = dateutil.parser.parse(candidate, fuzzy=True)
                break
            except (ValueError, OverflowError, TypeError):
                continue
    if dt is None:
        return None, False
    has_tz = dt.tzinfo is not None and dt.utcoffset() is not None
    # RFC 5322 "-0000" means "unknown zone"; parsedate_to_datetime returns naive.
    if not has_tz:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc), has_tz


def _split_clauses(text: str) -> dict[str, str]:
    """Split a Received value (without its date) into keyword clauses, ignoring
    keywords that appear inside parenthesised comments."""
    depth = 0
    marks: list[tuple[int, str]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and (i == 0 or text[i - 1].isspace()):
            for kw in KEYWORDS:
                end = i + len(kw)
                if text[i:end].lower() == kw and (end == n or text[end].isspace()):
                    marks.append((i, kw))
                    i = end - 1
                    break
        i += 1
    clauses: dict[str, str] = {}
    for idx, (pos, kw) in enumerate(marks):
        start = pos + len(kw)
        stop = marks[idx + 1][0] if idx + 1 < len(marks) else n
        value = " ".join(text[start:stop].split())
        if kw not in clauses:  # keep the first occurrence of each keyword
            clauses[kw] = value
    return clauses


def _split_host(value: str) -> tuple[str, str]:
    """``"helo.name (rdns.name [1.2.3.4])"`` -> ("helo.name", "rdns.name [1.2.3.4]")"""
    if not value:
        return "", ""
    m = re.match(r"^([^\s(]*)\s*(.*)$", value)
    name, rest = (m.group(1), m.group(2)) if m else (value, "")
    rest = rest.strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    return name.strip("[]") if _parse_ip(name.strip("[]")) else name, rest


@dataclass
class Hop:
    index: int = 0
    raw: str = ""
    from_host: str = ""
    from_detail: str = ""
    by_host: str = ""
    by_detail: str = ""
    protocol: str = ""
    via: str = ""
    msg_id: str = ""
    for_addr: str = ""
    timestamp: datetime | None = None
    timestamp_has_tz: bool = False
    from_ips: list[str] = field(default_factory=list)
    by_ips: list[str] = field(default_factory=list)
    delay: float | None = None
    clock_skew: float | None = None
    tls: bool = False
    geo: dict | None = None

    @property
    def from_ip(self) -> str | None:
        public = [ip for ip in self.from_ips if is_public_ip(ip)]
        if public:
            return public[0]
        return self.from_ips[0] if self.from_ips else None

    def to_dict(self) -> dict:
        return {
            "hop": self.index,
            "from": self.from_host,
            "from_detail": self.from_detail,
            "from_ip": self.from_ip,
            "from_ip_public": bool(self.from_ip and is_public_ip(self.from_ip)),
            "by": self.by_host,
            "by_detail": self.by_detail,
            "with": self.protocol,
            "via": self.via,
            "id": self.msg_id,
            "for": self.for_addr,
            "tls": self.tls,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_has_tz": self.timestamp_has_tz,
            "delay": self.delay,
            "clock_skew": self.clock_skew,
            "geo": self.geo,
            "raw": self.raw,
        }


_TLS_RE = re.compile(r"\b(ESMTPS|ESMTPSA|UTF8SMTPS|LMTPS|TLS\s*1\.[0-3]|TLSv1|version=TLS|cipher=)", re.IGNORECASE)


def parse_received(value: str) -> Hop:
    raw = " ".join(value.split())
    body, date_text = raw, ""
    if ";" in raw:
        body, date_text = raw.rsplit(";", 1)
        # A ';' can occur in comments with no date after it.
        if not re.search(r"\d", date_text):
            body, date_text = raw, ""
    clauses = _split_clauses(body)
    hop = Hop(raw=raw)
    hop.from_host, hop.from_detail = _split_host(clauses.get("from", ""))
    hop.by_host, hop.by_detail = _split_host(clauses.get("by", ""))
    with_clause = re.sub(r"\(.*", "", clauses.get("with", "")).strip()
    hop.protocol = with_clause[:60]
    hop.via = clauses.get("via", "")
    hop.msg_id = clauses.get("id", "").split(" ")[0] if clauses.get("id") else ""
    hop.for_addr = clauses.get("for", "").strip("<>;") if clauses.get("for") else ""
    hop.from_ips = find_ips(clauses.get("from", ""))
    hop.by_ips = find_ips(clauses.get("by", ""))
    hop.tls = bool(_TLS_RE.search(raw))
    hop.timestamp, hop.timestamp_has_tz = parse_date(date_text)
    return hop


def build_hops(received_values: list[str]) -> list[Hop]:
    """Received headers are prepended, so the list is newest-first.
    Returns hops oldest-first (hop 1 = origin) with per-hop delays."""
    hops = [parse_received(v) for v in received_values if v and v.strip()]
    hops = [h for h in hops if h.from_host or h.by_host or h.timestamp]
    hops.reverse()
    prev_ts = None
    for i, hop in enumerate(hops, 1):
        hop.index = i
        if hop.timestamp and prev_ts:
            diff = (hop.timestamp - prev_ts).total_seconds()
            if diff < 0:
                hop.clock_skew = diff
                hop.delay = 0.0
            else:
                hop.delay = diff
        if hop.timestamp:
            prev_ts = hop.timestamp
    return hops
