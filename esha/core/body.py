"""Static, offline inspection of a message body (when a full .eml is supplied):
links, attachments and HTML forms. Nothing is fetched or executed."""
from __future__ import annotations

import email
import ipaddress
import re
from email import policy
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from .domains import aligned, is_punycode, lookalike_brand, org_domain

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "bl.ink", "lnkd.in", "qrco.de", "short.io", "v.gd",
}
# Free hosting / file-sharing / form builders that are heavily abused for credential phishing.
ABUSED_HOSTS = {
    "firebaseapp.com", "web.app", "appspot.com", "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com",
    "github.io", "glitch.me", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "herokuapp.com", "azurewebsites.net", "windows.net", "storage.googleapis.com",
    "sharepoint.com", "onedrive.live.com", "1drv.ms", "dropbox.com", "docs.google.com", "forms.gle", "sites.google.com",
    "jotform.com", "typeform.com", "formstack.com", "wetransfer.com", "ipfs.io", "dweb.link", "s3.amazonaws.com",
    "notion.site", "canva.site", "framer.app", "webflow.io", "square.site", "godaddysites.com", "mystrikingly.com",
}
RISKY_EXT = {
    "exe": "executable", "scr": "executable", "com": "executable", "pif": "executable", "bat": "script", "cmd": "script",
    "ps1": "script", "vbs": "script", "vbe": "script", "js": "script", "jse": "script", "wsf": "script", "hta": "script",
    "lnk": "shortcut", "url": "shortcut", "iso": "disk image", "img": "disk image", "vhd": "disk image", "vhdx": "disk image",
    "msi": "installer", "msix": "installer", "appx": "installer", "jar": "executable", "dll": "executable", "cpl": "executable",
    "html": "HTML page", "htm": "HTML page", "shtml": "HTML page", "svg": "SVG (can contain script)", "xhtml": "HTML page",
    "docm": "macro document", "xlsm": "macro document", "pptm": "macro document", "xlam": "macro document", "dotm": "macro document",
    "one": "OneNote file", "chm": "help file", "reg": "registry file", "zip": "archive", "rar": "archive", "7z": "archive",
    "gz": "archive", "ace": "archive", "cab": "archive", "xll": "Excel add-in", "iqy": "Excel query", "slk": "Excel query",
}
HIGH_RISK_KINDS = {"executable", "script", "shortcut", "disk image", "installer", "HTML page", "SVG (can contain script)",
                   "macro document", "OneNote file", "help file", "Excel add-in", "Excel query", "registry file"}
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'()\[\]]+", re.I)


class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self.forms: list[dict] = []
        self._a: dict | None = None
        self.has_password = False
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._a = {"href": a["href"].strip(), "text": ""}
        elif tag == "form":
            action = (a.get("action") or "").strip()
            self.forms.append({"action": action, "method": (a.get("method") or "get").lower()})
            if action.lower().startswith(("http://", "https://", "//")):
                self.links.append({"href": action if not action.startswith("//") else "https:" + action, "text": "(form submits here)"})
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.has_password = True
        elif tag == "script":
            self.scripts += 1
        elif tag in ("meta",) and (a.get("http-equiv") or "").lower() == "refresh":
            m = re.search(r"url=(.+)", a.get("content") or "", re.I)
            if m:
                self.links.append({"href": m.group(1).strip(" '\""), "text": "(meta refresh)"})

    def handle_data(self, data):
        if self._a is not None:
            self._a["text"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._a is not None:
            self._a["text"] = " ".join(self._a["text"].split())[:200]
            self.links.append(self._a)
            self._a = None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{8}", host or "", re.I))  # decimal / hex IPs


def _domain_in_text(text: str) -> str:
    m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:\s]|$)", (text or "").lower())
    return m.group(1) if m else ""


def _link_flags(href: str, text: str, from_domain: str) -> list[str]:
    flags = []
    scheme = href.split(":", 1)[0].lower() if ":" in href else ""
    if scheme in ("javascript", "vbscript"):
        return ["script link"]
    if scheme == "data":
        return ["data: URI (embedded page)"]
    if scheme == "file" or href.startswith("\\\\"):
        return ["file / network-share link"]
    host = _host(href)
    if not host:
        return flags
    if _is_ip(host):
        flags.append("raw IP address")
    if org_domain(host) in SHORTENERS or host in SHORTENERS:
        flags.append("URL shortener")
    if any(host == h or host.endswith("." + h) for h in ABUSED_HOSTS):
        flags.append("free hosting often abused for phishing")
    if is_punycode(host):
        flags.append("punycode domain")
    la = lookalike_brand(host)
    if la:
        flags.append(f"look-alike of {la['legit_domain']}")
    if "@" in (urlsplit(href).netloc or ""):
        flags.append("credentials-style @ in URL")
    shown = _domain_in_text(text)
    if shown and not aligned(shown, host) and shown not in href.lower():
        flags.append(f"text shows {shown} but links to {host}")
    if re.search(r"(redirect|url|goto|next|target|dest|link)=https?%3a|=https?://", href, re.I):
        flags.append("open redirect / tracking wrapper")
    if href.lower().startswith("http://"):
        flags.append("not HTTPS")
    return flags


def analyze_body(raw: str, from_domain: str = "") -> dict | None:
    """Returns None when the input has no body (headers only)."""
    msg = email.message_from_string(raw, policy=policy.default)
    has_body = bool(msg.is_multipart() or (msg.get_payload() or "").strip())
    if not has_body:
        return None
    links: list[dict] = []
    attachments: list[dict] = []
    forms: list[dict] = []
    has_password = False
    scripts = 0
    text_seen = set()

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = (part.get_content_disposition() or "").lower()
        if fname or disp == "attachment" or (not ctype.startswith("text/") and ctype != "message/rfc822"):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            name = fname or "(unnamed)"
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            kind = RISKY_EXT.get(ext)
            double = bool(re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.[a-z0-9]{2,4}$", name, re.I))
            sniff = ""
            if payload[:2] == b"MZ":
                sniff = "Windows executable"
            elif payload[:4] == b"PK\x03\x04" and ext not in ("zip", "docx", "xlsx", "pptx", "jar", "odt", "ods"):
                sniff = "ZIP archive"
            elif b"<html" in payload[:2048].lower() or b"<script" in payload[:4096].lower():
                sniff = "HTML" if ext not in ("html", "htm") else ""
            attachments.append({
                "filename": name, "content_type": ctype, "size": len(payload), "extension": ext,
                "kind": kind, "risky": bool(kind in HIGH_RISK_KINDS or double or sniff == "Windows executable"),
                "double_extension": double, "content_mismatch": sniff,
            })
            if ctype in ("text/html",) or ext in ("html", "htm", "shtml", "xhtml", "svg"):
                try:
                    p = _HTML()
                    p.feed(payload.decode("utf-8", "replace"))
                    forms += p.forms
                    has_password |= p.has_password
                    scripts += p.scripts
                    for lk in p.links:
                        lk["source"] = name
                        links.append(lk)
                except Exception:
                    pass
            continue
        try:
            content = part.get_content()
        except Exception:
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            p = _HTML()
            try:
                p.feed(content)
            except Exception:
                pass
            for lk in p.links:
                lk["source"] = "body"
                links.append(lk)
                text_seen.add(lk["href"])
            forms += p.forms
            has_password |= p.has_password
            scripts += p.scripts
        else:
            for u in URL_RE.findall(content):
                u = u.rstrip(".,;:!?")
                if u not in text_seen:
                    links.append({"href": u, "text": "", "source": "body"})
                    text_seen.add(u)

    seen, uniq = set(), []
    for lk in links:
        key = (lk["href"], lk["text"])
        if key in seen:
            continue
        seen.add(key)
        href = unquote(lk["href"]) if lk["href"].lower().startswith(("http%3a", "https%3a")) else lk["href"]
        host = _host(href)
        uniq.append({"href": href[:2000], "text": lk["text"], "host": host, "source": lk["source"],
                     "same_org_as_sender": aligned(host, from_domain) if host and from_domain else False,
                     "flags": _link_flags(href, lk["text"], from_domain)})
    return {
        "links": uniq[:500],
        "link_count": len(uniq),
        "domains": sorted({lk["host"] for lk in uniq if lk["host"]}),
        "attachments": attachments,
        "forms": forms,
        "password_field": has_password,
        "scripts": scripts,
    }
