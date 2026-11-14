"""Static inspection of attachment bytes: HTML smuggling, archive and disk-image
listings, and calendar invites.

Nothing here decompresses, extracts, renders or executes content. Archives are
read from their directory structures only (ZIP central directory, ISO 9660
directory records); other containers get a bounded scan for file names.
Every loop is capped so hostile input can't make it slow.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile

# Kinds of files that are dangerous to find inside an archive or disk image.
EXEC_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk",
            "url", "msi", "msix", "dll", "cpl", "jar", "reg", "chm", "xll", "iqy", "slk", "one", "appx", "appref-ms"}
DOC_RISK_EXT = {"html", "htm", "shtml", "xhtml", "svg", "docm", "xlsm", "pptm", "dotm", "xlam", "iso", "img", "vhd",
                "vhdx"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "lzh", "z", "zipx", "iso",
               "img", "vhd", "vhdx"}
OFFICE_ZIP_EXT = {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "xltx", "potx", "odt", "ods", "odp", "jar",
                  "apk", "epub", "vsdx", "xps", "oxps", "msix", "appx", "nupkg", "whl", "kmz"}

MAX_ENTRIES = 1000  # listed entries per container
MAX_SCAN = 8 * 1024 * 1024  # bytes scanned for file names in unparsed containers


def _ext(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def classify_entries(names: list[str]) -> dict:
    """Split a container listing into dangerous files and nested archives."""
    risky, nested = [], []
    for n in names:
        e = _ext(n.rstrip(";1"))
        double = bool(re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.[a-z0-9]{2,4}$", n, re.I))
        if e in EXEC_EXT or double:
            risky.append({"name": n, "kind": "program, script or shortcut" if not double else "double extension",
                          "severe": True})
        elif e in DOC_RISK_EXT:
            risky.append({"name": n, "kind": "page, macro document or disk image", "severe": False})
        if e in ARCHIVE_EXT:
            nested.append(n)
    return {"risky": risky, "nested": nested}


# ------------------------------------------------------------------- ZIP
def _zip(payload: bytes) -> dict | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
        infos = zf.infolist()[:MAX_ENTRIES]
    except (zipfile.BadZipFile, ValueError, OSError, EOFError, struct.error, NotImplementedError):
        return None
    names = [i.filename for i in infos if not i.is_dir()]
    encrypted = [i.filename for i in infos if i.flag_bits & 0x1 or i.compress_type == 99]  # 99 = WinZip AES
    return {"format": "ZIP", "entries": names, "encrypted": bool(encrypted), "encrypted_entries": encrypted[:50],
            "listing": "complete"}


# ------------------------------------------------------------ ISO 9660
_SECTOR = 2048


def _iso(payload: bytes) -> dict | None:
    """List files from ISO 9660 directory records (Joliet names when present)."""
    if len(payload) < 17 * _SECTOR:
        return None
    pvd = joliet = None
    for i in range(16, min(32, len(payload) // _SECTOR)):
        vd = payload[i * _SECTOR:(i + 1) * _SECTOR]
        if vd[1:6] != b"CD001":
            break
        if vd[0] == 1 and pvd is None:
            pvd = vd
        elif vd[0] == 2 and vd[88:91] in (b"%/@", b"%/C", b"%/E"):
            joliet = vd
        elif vd[0] == 255:
            break
    vd = joliet or pvd
    if vd is None:
        return None
    enc = "utf-16-be" if vd is joliet else "latin-1"
    root = vd[156:190]
    names: list[str] = []
    seen: set[int] = set()
    stack = [(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "", 0)]
    while stack and len(names) < MAX_ENTRIES and len(seen) < 256:
        lba, size, prefix, depth = stack.pop()
        if lba in seen or depth > 8:
            continue
        seen.add(lba)
        start, end = lba * _SECTOR, min(lba * _SECTOR + min(size, 1024 * 1024), len(payload))
        pos = start
        while pos < end and len(names) < MAX_ENTRIES:
            rec_len = payload[pos]
            if rec_len == 0:  # records don't cross sectors; skip to the next one
                pos = (pos // _SECTOR + 1) * _SECTOR
                continue
            rec = payload[pos:pos + rec_len]
            pos += rec_len
            if len(rec) < 34:
                break
            name_len = rec[32]
            raw = rec[33:33 + name_len]
            if raw in (b"\x00", b"\x01"):
                continue
            name = raw.decode(enc, "replace").split(";")[0].rstrip(".")
            path = f"{prefix}{name}"
            if rec[25] & 0x02:  # directory
                stack.append((struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0], path + "/", depth + 1))
            else:
                names.append(path)
    return {"format": "ISO 9660", "entries": names, "encrypted": False, "listing": "complete"}


# --------------------------------------------- other containers: name scan
_NAME_EXTS = sorted(EXEC_EXT | {"zip", "rar", "7z", "iso", "img", "vhd", "vhdx", "html", "htm", "svg"})
_NAME_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _-.()[]")
# Find the extension first, then walk back over name characters. A single
# regex with a {1,80} prefix would backtrack badly on long runs of letters.
_ASCII_EXT = re.compile(rb"\.(?:" + b"|".join(e.encode() for e in _NAME_EXTS) + rb")(?![A-Za-z0-9])", re.IGNORECASE)
_UTF16_EXT = re.compile(rb"\.\x00(?:" + b"|".join(
    b"".join(re.escape(bytes([c])) + b"\x00" for c in e.encode()) for e in _NAME_EXTS) + rb")(?![A-Za-z0-9]\x00)",
    re.IGNORECASE)


def _scan_names(payload: bytes) -> list[str]:
    """File names that appear in raw container bytes (VHD, UDF, RAR headers).

    Approximate: it can't see names in compressed or encrypted headers, and
    may pick up names mentioned in file contents.
    """
    data = payload[:MAX_SCAN]
    found: list[str] = []
    for n, m in enumerate(_ASCII_EXT.finditer(data)):
        if n >= 2000:
            break
        j = m.start()
        while j > 0 and m.start() - j < 80 and data[j - 1] in _NAME_CHARS:
            j -= 1
        found.append(data[j:m.end()].decode("ascii", "replace"))
    for n, m in enumerate(_UTF16_EXT.finditer(data)):
        if n >= 2000:
            break
        j = m.start()
        while j > 1 and m.start() - j < 160 and data[j - 1] == 0 and data[j - 2] in _NAME_CHARS:
            j -= 2
        found.append(data[j:m.end()].decode("utf-16-le", "replace"))
    out = []
    for name in found:
        name = name.strip(" .")
        stem = name.rsplit(".", 1)[0].strip(" ._-")
        if stem and name not in out and not name.lower().startswith(("http", "www.")):
            out.append(name)
        if len(out) >= 200:
            break
    return out


MAGIC = [
    (b"Rar!\x1a\x07", "RAR"), (b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"conectix", "VHD"), (b"vhdxfile", "VHDX"),
    (b"MSCF", "CAB"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
]


def inspect_container(payload: bytes, ext: str) -> dict | None:
    """Return a listing for archives and disk images, or None for other files.

    Keys: format, entries, encrypted, listing ("complete", "names found in raw
    data" or "not listed"), risky [{name, kind, severe}], nested [names].
    """
    ext = (ext or "").lower()
    if ext in OFFICE_ZIP_EXT:
        return None
    info = None
    if payload[:4] in (b"PK\x03\x04", b"PK\x05\x06") or ext in ("zip", "zipx"):
        info = _zip(payload)
    if info is None and (ext in ("iso", "img") or payload[0x8001:0x8006] == b"CD001"):
        info = _iso(payload)
    if info is None:
        fmt = next((name for magic, name in MAGIC if payload.startswith(magic)), None)
        # VHD's "conectix" footer is at the end of the file (and copied at the start for dynamic disks).
        if fmt is None and payload[-512:-504] == b"conectix":
            fmt = "VHD"
        if fmt is None and ext in ("iso", "img", "vhd", "vhdx"):
            fmt = {"iso": "ISO (UDF)", "img": "disk image", "vhd": "VHD", "vhdx": "VHDX"}[ext]
        if fmt is None and ext not in ARCHIVE_EXT:
            return None
        fmt = fmt or ext.upper()
        compressed = fmt in ("7-Zip", "gzip", "bzip2", "xz", "CAB")
        names = [] if compressed else _scan_names(payload)
        info = {"format": fmt, "entries": names, "encrypted": False,
                "listing": "names found in raw data" if names else "not listed"}
        if fmt == "RAR" and _rar_encrypted(payload):
            info["encrypted"] = True
    info.update(classify_entries(info["entries"]))
    info["entry_count"] = len(info["entries"])
    info["entries"] = info["entries"][:200]
    return info


def _rar_encrypted(payload: bytes) -> bool:
    """RAR5 archives with encrypted headers start with an encryption header (type 4);
    RAR4 sets flag 0x0080 (encrypted headers) in the main header or 0x0004 in file headers."""
    if payload.startswith(b"Rar!\x1a\x07\x01\x00"):
        # RAR5: CRC32 (4) + vint size + vint type
        p = 12
        while p < min(len(payload), 24) and payload[p] & 0x80:
            p += 1
        return p + 1 < len(payload) and payload[p + 1] == 4
    if payload.startswith(b"Rar!\x1a\x07\x00") and len(payload) >= 20:
        main_flags = struct.unpack_from("<H", payload, 10)[0]
        if main_flags & 0x0080:
            return True
        pos = 7 + struct.unpack_from("<H", payload, 12)[0]
        if pos + 5 <= len(payload) and payload[pos + 2] == 0x74:  # file header
            return bool(struct.unpack_from("<H", payload, pos + 3)[0] & 0x0004)
    return False


# --------------------------------------------------------- HTML smuggling
_SMUGGLING = [
    ("atob() base64 decoding", re.compile(r"\batob\s*\(", re.I)),
    ("Blob built in the browser", re.compile(r"\bnew\s+Blob\s*\(|\bBlob\s*\(\s*\[", re.I)),
    ("msSaveOrOpenBlob / msSaveBlob download", re.compile(r"\bmsSave(?:OrOpen)?Blob\b", re.I)),
    ("createObjectURL download link", re.compile(r"\bcreateObjectURL\s*\(", re.I)),
    ("scripted download attribute", re.compile(r"\.download\s*=|\bsetAttribute\s*\(\s*['\"]download['\"]", re.I)),
    ("embedded file as data: URI", re.compile(
        r"data:application/(?:octet-stream|zip|x-zip-compressed|x-msdownload|x-iso9660-image|vnd\.ms-|x-rar|x-7z)[^;,\"']{0,40};base64",
        re.I)),
    ("obfuscated script (fromCharCode / unescape / eval)", re.compile(
        r"String\.fromCharCode\s*\(|\bunescape\s*\(|\beval\s*\(|\bdocument\.write\s*\(\s*(?:unescape|atob)", re.I)),
]
_BASE64_CHARS = re.compile(r"[A-Za-z0-9+/]+")  # each run is matched once, so this stays linear


def html_smuggling(text: str) -> list[str]:
    """Indicators that an HTML/SVG file assembles a download in the browser."""
    text = text[:4_000_000]
    hits = [label for label, rx in _SMUGGLING if rx.search(text)]
    if any(m.end() - m.start() >= 8192 for m in _BASE64_CHARS.finditer(text)):
        hits.append("large base64 blob (8 KB or more)")
    return hits


# ------------------------------------------------------- calendar invites
_URL = re.compile(r"\bhttps?://[^\s<>\"'\\]+", re.I)


def parse_ics(text: str) -> dict:
    """Minimal RFC 5545 reader: method, organiser, attendees, summary and links."""
    text = re.sub(r"\r?\n[ \t]", "", text[:1_000_000])  # unfold
    out = {"method": "", "organizer": "", "organizer_name": "", "attendees": [], "summary": "", "links": []}
    in_event = False
    for line in text.splitlines()[:20000]:
        if ":" not in line:
            continue
        head, value = line.split(":", 1)
        name, _, params = head.partition(";")
        name = name.upper()
        if name == "BEGIN" and value.strip().upper() == "VEVENT":
            in_event = True
        elif name == "METHOD":
            out["method"] = value.strip().upper()
        elif name == "ORGANIZER" and not out["organizer"]:
            out["organizer"] = re.sub(r"^mailto:", "", value.strip(), flags=re.I)
            m = re.search(r"CN=\"?([^;\"]+)", params, re.I)
            out["organizer_name"] = m.group(1) if m else ""
        elif name == "ATTENDEE" and len(out["attendees"]) < 100:
            out["attendees"].append(re.sub(r"^mailto:", "", value.strip(), flags=re.I))
        elif name == "SUMMARY" and in_event and not out["summary"]:
            out["summary"] = value.replace("\\,", ",").replace("\\n", " ").strip()[:200]
        if name in ("DESCRIPTION", "LOCATION", "URL", "ATTACH", "X-ALT-DESC", "COMMENT", "CONFERENCE",
                    "X-GOOGLE-CONFERENCE", "X-MICROSOFT-SKYPETEAMSMEETINGURL", "X-MICROSOFT-ONLINEMEETINGCONFLINK"):
            for u in _URL.findall(value.replace("\\n", " ").replace("\\,", ",").replace("\\;", ";")):
                u = u.rstrip(".,;:!?)")
                if u not in out["links"] and len(out["links"]) < 100:
                    out["links"].append(u)
    return out
