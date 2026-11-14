"""Indicators of compromise (IOCs) from a finished report.

Works on the report dict alone, so it also runs on a saved JSON report.
Recipient addresses and the receiving side's infrastructure are left out:
indicators describe the sender, the links and the attachments.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .domains import aligned, cousin_domain, lookalike_brand


def defang_domain(domain: str) -> str:
    return (domain or "").replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]") if "." in ip else ip.replace(":", "[:]")


def defang_email(addr: str) -> str:
    local, _, dom = (addr or "").rpartition("@")
    return f"{local}[@]{defang_domain(dom)}" if local else defang_domain(addr)


def defang_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.replace(".", "[.]")
    scheme = re.sub(r"^http", "hxxp", parts.scheme, flags=re.IGNORECASE)
    rest = url[len(parts.scheme) + 3:] if "://" in url[:12] else url
    host = parts.netloc
    return f"{scheme}[://]{rest.replace(host, defang_domain(host), 1)}" if parts.scheme else defang_domain(url)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def extract(report: dict) -> dict:
    s = report.get("summary") or {}
    auth = report.get("auth") or {}
    content = report.get("content") or {}
    level = (report.get("score") or {}).get("level")
    from_domain = (s.get("from") or {}).get("domain", "")
    origin_hop = (report.get("origin") or {}).get("hop")

    ips: dict[str, dict] = {}

    def add_ip(ip, role, geo=None, hop=None):
        if not ip:
            return
        e = ips.setdefault(ip, {"value": ip, "defanged": defang_ip(ip), "roles": [], "country": (geo or {}).get("country"),
                                "hop": hop, "suspicious": False})
        if role not in e["roles"]:
            e["roles"].append(role)
        if role == "origin" and level == "high":
            e["suspicious"] = True

    for h in report.get("hops") or []:
        if h.get("from_ip") and h.get("from_ip_public"):
            add_ip(h["from_ip"], "origin" if h.get("hop") == origin_hop else "relay", h.get("geo"), h.get("hop"))
    oh = s.get("originating_ip_header")
    if oh:
        add_ip(oh.get("ip"), oh.get("header", "x-originating-ip"), oh.get("geo"))

    emails: dict[str, dict] = {}

    def add_email(addr, role):
        addr = (addr or "").strip().lower()
        if "@" not in addr:
            return
        e = emails.setdefault(addr, {"value": addr, "defanged": defang_email(addr), "roles": []})
        if role not in e["roles"]:
            e["roles"].append(role)

    add_email((s.get("from") or {}).get("address"), "from")
    add_email((s.get("sender") or {}).get("address"), "sender")
    for rt in s.get("reply_to") or []:
        add_email(rt.get("address"), "reply-to")
    add_email((s.get("return_path") or {}).get("address"), "return-path")

    domains: dict[str, dict] = {}
    flagged_hosts = {lk["host"] for lk in content.get("links", []) if lk.get("host") and lk.get("flags")}

    def add_domain(d, role):
        d = (d or "").strip().lower().rstrip(".")
        if not d or "." not in d or _is_ip(d):
            return
        e = domains.setdefault(d, {"value": d, "defanged": defang_domain(d), "roles": [], "suspicious": False})
        if role not in e["roles"]:
            e["roles"].append(role)
        if lookalike_brand(d) or (from_domain and cousin_domain(d, from_domain)) or d in flagged_hosts:
            e["suspicious"] = True

    add_domain(from_domain, "from")
    for rt in s.get("reply_to") or []:
        add_domain(rt.get("domain"), "reply-to")
    add_domain((s.get("return_path") or {}).get("domain"), "return-path")
    add_domain((s.get("sender") or {}).get("domain"), "sender")
    for row in auth.get("alignment") or []:
        label = row.get("label", "")
        role = {"SPF envelope sender": "envelope", "DKIM signer (d=)": "dkim", "Message-ID": "message-id",
                "Sending server (HELO)": "helo"}.get(label)
        if role:
            add_domain(row.get("domain"), role)
    for lk in content.get("links") or []:
        host = (lk.get("host") or "").strip("[]")
        if _is_ip(host):
            add_ip(host, "link")
            if lk.get("flags"):
                ips[host]["suspicious"] = True
        else:
            add_domain(host, "link")
    for cal in content.get("calendar") or []:
        org = (cal.get("organizer") or "").rpartition("@")[2]
        add_domain(org, "calendar organiser")
        add_email(cal.get("organizer"), "calendar organiser")

    urls, seen = [], set()
    for lk in content.get("links") or []:
        href = lk.get("href") or ""
        if not re.match(r"https?://", href, re.IGNORECASE) or href in seen:
            continue
        seen.add(href)
        urls.append({"value": href, "defanged": defang_url(href), "host": lk.get("host", ""), "source": lk.get("source", ""),
                     "flags": lk.get("flags", []), "suspicious": bool(lk.get("flags")),
                     "same_org_as_sender": bool(from_domain and lk.get("host") and aligned(lk["host"], from_domain))})

    files = []
    for a in content.get("attachments") or []:
        c = a.get("container") or {}
        files.append({"filename": a.get("filename"), "sha256": a.get("sha256"), "md5": a.get("md5"), "size": a.get("size"),
                      "content_type": a.get("content_type"),
                      "suspicious": bool(a.get("risky") or a.get("smuggling") or c.get("encrypted") or c.get("risky")),
                      "contains": c.get("entries", [])[:50]})

    return {
        "ips": list(ips.values()), "domains": list(domains.values()), "urls": urls, "emails": list(emails.values()),
        "files": files,
        "message": {"subject": s.get("subject", ""), "message_id": s.get("message_id", ""), "date": s.get("date_utc") or s.get("date"),
                    "x_mailer": s.get("mailer", "")},
        "counts": {"ips": len(ips), "domains": len(domains), "urls": len(urls), "emails": len(emails), "files": len(files)},
    }
