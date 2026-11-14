"""Turn uploaded bytes into text for the analyzer: .eml/.txt/.mbox as text,
Outlook .msg rebuilt into an RFC 822 message. Shared by the web app, the API,
the command line and the in-browser engine."""
from __future__ import annotations

from .msg import MsgError, is_msg, msg_to_eml

FILE_SUFFIXES = (".eml", ".mbox", ".msg")

__all__ = ["MsgError", "decode_bytes", "decode_text"]


def decode_text(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")  # pragma: no cover - latin-1 always decodes


def decode_bytes(data: bytes, filename: str = "", rfc822: bool = False) -> tuple[str, bool, dict | None]:
    """Return (text, from_file, input_info). ``from_file`` is True for whole
    messages (as opposed to pasted headers). Raises MsgError for unreadable .msg files."""
    name = (filename or "").lower()
    if is_msg(data):
        text, info = msg_to_eml(data)
        return text, True, info
    if name.endswith(".msg"):
        raise MsgError("This file is named .msg but is not an Outlook message file.")
    return decode_text(data), rfc822 or name.endswith(FILE_SUFFIXES), None
