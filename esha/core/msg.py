"""Outlook .msg support: rebuild an RFC 822 message from an OLE compound file.

A .msg file is a Compound File Binary (OLE) container of MAPI properties
([MS-OXMSG]). ESHA only needs a few of them:

* PR_TRANSPORT_MESSAGE_HEADERS (0x007D): the original internet headers,
  including Received, Authentication-Results and DKIM-Signature. Present on
  received mail, missing on drafts and sent items.
* PR_BODY (0x1000) and PR_HTML (0x1013): the plain-text and HTML bodies.
* Attachment storages: file name, MIME type and data, plus embedded .msg
  attachments, which are converted recursively.

Only olefile (pure Python, BSD) is needed, so this also runs in the browser.
Nothing is executed or rendered; RTF-only bodies are not decoded.
"""
from __future__ import annotations

import io
import re
import struct
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from email.utils import format_datetime

try:
    import olefile
except Exception:  # pragma: no cover - optional at import time
    olefile = None

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_MSG_BYTES = 50 * 1024 * 1024
MAX_ATTACHMENTS = 200
MAX_DEPTH = 3  # embedded .msg inside .msg
_DROP_HEADERS = {"content-type", "content-transfer-encoding", "mime-version"}


class MsgError(ValueError):
    pass


def is_msg(data: bytes) -> bool:
    return data[:8] == OLE_MAGIC


def _filetime(value: int) -> datetime | None:
    if not value:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


class _Storage:
    """A message (or embedded message / attachment) storage inside the OLE file."""

    def __init__(self, ole, prefix: list[str]):
        self.ole, self.prefix = ole, prefix

    def _path(self, name):
        return self.prefix + [name]

    def raw(self, name: str) -> bytes | None:
        path = self._path(name)
        if self.ole.exists("/".join(path)):
            try:
                return self.ole.openstream(path).read()
            except Exception:
                return None
        return None

    def string(self, prop: str) -> str:
        """Read a string property (PT_UNICODE 001F, falling back to PT_STRING8 001E)."""
        data = self.raw(f"__substg1.0_{prop}001F")
        if data is not None:
            return data.decode("utf-16-le", "replace").rstrip("\x00")
        data = self.raw(f"__substg1.0_{prop}001E")
        if data is not None:
            return data.decode("cp1252", "replace").rstrip("\x00")
        return ""

    def binary(self, prop: str) -> bytes | None:
        return self.raw(f"__substg1.0_{prop}0102")

    def fixed_props(self, header_size: int) -> dict[int, int]:
        """Fixed-size properties from __properties_version1.0 as {tag: 8-byte value}."""
        data = self.raw("__properties_version1.0") or b""
        out = {}
        for off in range(header_size, len(data) - 15, 16):
            tag, _flags, value = struct.unpack_from("<IIQ", data, off)
            out[tag] = value
        return out

    def children(self, startswith: str) -> list[list[str]]:
        found = set()
        for entry in self.ole.listdir(streams=True, storages=True):
            if len(entry) > len(self.prefix) and entry[:len(self.prefix)] == self.prefix:
                name = entry[len(self.prefix)]
                if name.startswith(startswith):
                    found.add(name)
        return [self.prefix + [n] for n in sorted(found)]


def _strip_mime_headers(raw: str) -> str:
    """Drop Content-Type / Content-Transfer-Encoding / MIME-Version (the body is rebuilt),
    keeping every other header line exactly as it was, folding included."""
    out, keep = [], True
    for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line.strip():
            continue
        if line[:1] in (" ", "\t"):
            if keep:
                out.append(line)
            continue
        name = line.split(":", 1)[0].strip().lower()
        keep = name not in _DROP_HEADERS
        if keep:
            out.append(line)
    return "\n".join(out)


def _synth_headers(st: _Storage, top: bool) -> tuple[str, list[str]]:
    """Headers rebuilt from MAPI properties when there are no transport headers."""
    props = st.fixed_props(32 if top else 24)
    lines = []
    name = st.string("0042") or st.string("0C1A")
    addr = st.string("5D02") or st.string("5D01") or st.string("0065") or st.string("0C1F")
    if "@" not in addr:
        addr = ""  # Exchange X.500 address, not an internet address
    if name or addr:
        lines.append(f"From: {name} <{addr}>" if addr else f"From: {name}")
    to, cc = [], []
    for rpath in st.children("__recip_version1.0_#"):
        r = _Storage(st.ole, rpath)
        raddr = r.string("39FE") or r.string("3003")
        rname = r.string("3001")
        rtype = r.fixed_props(8).get(0x0C150003, 1)
        entry = f"{rname} <{raddr}>" if raddr and "@" in raddr else rname
        (cc if rtype == 2 else to).append(entry)
    if not to and st.string("0E04"):
        to = [st.string("0E04")]
    if to:
        lines.append("To: " + ", ".join(to))
    if cc:
        lines.append("Cc: " + ", ".join(cc))
    subj = st.string("0037")
    if subj:
        lines.append(f"Subject: {subj}")
    when = _filetime(props.get(0x00390040, 0)) or _filetime(props.get(0x0E060040, 0))
    if when:
        lines.append(f"Date: {format_datetime(when)}")
    for prop, header in (("1035", "Message-ID"), ("1042", "In-Reply-To"), ("1039", "References")):
        v = st.string(prop)
        if v:
            lines.append(f"{header}: {v}")
    return "\n".join(lines), ["The .msg file has no transport headers (it was probably saved from Sent Items or Drafts), "
                              "so there is no relay route or authentication result. Headers were rebuilt from Outlook "
                              "properties."]


def _attachments(st: _Storage, depth: int, notes: list[str]) -> list:
    parts = []
    for apath in st.children("__attach_version1.0_#")[:MAX_ATTACHMENTS]:
        a = _Storage(st.ole, apath)
        fname = a.string("3707") or a.string("3704") or a.string("3001") or "(unnamed)"
        mime = a.string("370E") or "application/octet-stream"
        cid = a.string("3712")
        embedded = apath + ["__substg1.0_3701000D"]
        if st.ole.exists("/".join(embedded)):
            if depth >= MAX_DEPTH:
                notes.append(f"Embedded message {fname} is nested too deeply and was not analyzed.")
                continue
            inner, inner_notes = _convert(_Storage(st.ole, embedded), depth + 1, top=False)
            notes.extend(f"In attached message {fname}: {n}" for n in inner_notes)
            part = MIMEMessage(Parser().parsestr(inner))
            part.add_header("Content-Disposition", "attachment", filename=fname if fname.endswith(".msg") else fname + ".eml")
            parts.append(part)
            continue
        data = a.binary("3701")
        if data is None:
            notes.append(f"Attachment {fname} has no data (it may be a link or an OLE object).")
            data = b""
        maintype, _, subtype = mime.partition("/")
        if maintype == "application" or not subtype:
            part = MIMEApplication(data, subtype or "octet-stream")
        else:
            part = MIMEBase(maintype, subtype)
            part.set_payload(data)
            encoders.encode_base64(part)
        part.add_header("Content-Disposition", "inline" if cid else "attachment", filename=fname)
        if cid:
            part.add_header("Content-ID", f"<{cid.strip('<>')}>")
        parts.append(part)
    return parts


def _convert(st: _Storage, depth: int, top: bool) -> tuple[str, list[str]]:
    notes: list[str] = []
    transport = st.string("007D")
    if transport.strip():
        head = _strip_mime_headers(transport)
    else:
        head, n = _synth_headers(st, top)
        notes += n

    text = st.string("1000")
    html_bytes = st.binary("1013")
    html = html_bytes.decode("utf-8", "replace").rstrip("\x00") if html_bytes else st.string("1013")
    if not text and not html and (st.binary("1009") or st.raw("__substg1.0_10090102")):
        notes.append("The message body is stored only as compressed RTF, which ESHA does not decode.")

    body_parts = []
    if text:
        body_parts.append(MIMEText(text, "plain", "utf-8"))
    if html:
        body_parts.append(MIMEText(html, "html", "utf-8"))
    attachments = _attachments(st, depth, notes)
    if len(body_parts) > 1:
        alt = MIMEMultipart("alternative")
        for p in body_parts:
            alt.attach(p)
        body_parts = [alt]
    if attachments:
        mixed = MIMEMultipart("mixed")
        for p in body_parts + attachments:
            mixed.attach(p)
        mime = mixed
    elif body_parts:
        mime = body_parts[0]
    else:
        mime = MIMEText("", "plain", "utf-8")
    return head.rstrip("\n") + "\n" + mime.as_string(), notes


def msg_to_eml(data: bytes) -> tuple[str, dict]:
    """Convert .msg bytes to RFC 822 text. Returns (text, info) where info is
    {"format": "msg", "transport_headers": bool, "notes": [...]}."""
    if olefile is None:
        raise MsgError("Outlook .msg support needs the olefile package (pip install olefile).")
    if len(data) > MAX_MSG_BYTES:
        raise MsgError(f"The .msg file is larger than {MAX_MSG_BYTES // 1024 // 1024} MB.")
    if not is_msg(data):
        raise MsgError("Not an Outlook .msg file.")
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as e:
        raise MsgError(f"The .msg file could not be read: {e}") from None
    try:
        st = _Storage(ole, [])
        if not st.string("001A").upper().startswith("IPM") and not ole.exists("__substg1.0_0037001F") \
                and not ole.exists("__substg1.0_007D001F") and not ole.exists("__substg1.0_0037001E"):
            raise MsgError("This OLE file does not look like an Outlook message (no message class or subject).")
        text, notes = _convert(st, 0, top=True)
        has_transport = bool(st.string("007D").strip())
        message_class = re.sub(r"[^\x20-\x7e]", "", st.string("001A"))[:64]
    finally:
        ole.close()
    return text, {"format": "msg", "transport_headers": has_transport, "message_class": message_class, "notes": notes}
