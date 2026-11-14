"""Outlook .msg input."""
import io
from pathlib import Path

import pytest
from scripts_loader import make_samples

from esha.__main__ import main
from esha.app import create_app
from esha.core import analyze
from esha.core.inputs import decode_bytes
from esha.core.msg import MsgError, msg_to_eml

SAMPLES = Path(__file__).parent / "samples"


def analyze_msg(name):
    text, from_file, source = decode_bytes((SAMPLES / name).read_bytes(), name)
    return analyze(text, from_file=from_file, source=source)


def rules(r):
    return {f["rule_id"]: f for f in r["findings"]}


def test_received_msg_keeps_transport_headers_body_and_attachments():
    r = analyze_msg("outlook_phish.msg")
    assert r["meta"]["input"] == {"format": "msg", "transport_headers": True, "message_class": "IPM.Note", "notes": []}
    assert len(r["hops"]) == 3 and r["auth"]["dmarc"]["result"] == "fail"
    assert r["score"]["level"] == "high"
    f = rules(r)
    assert {"ESHA-102", "ESHA-404", "ESHA-402"} <= set(f)
    assert [a["filename"] for a in r["content"]["attachments"]] == ["Account_Verification.html"]
    assert all(h["name"].lower() != "content-type" or "multipart" in h["value"] for h in r["headers"])


def test_msg_and_eml_get_the_same_header_verdict():
    eml = analyze((SAMPLES / "phish_paypal.eml").read_text(), from_file=True)
    msg = analyze_msg("outlook_phish.msg")
    header_rules = {f["rule_id"] for f in eml["findings"] if f["category"] in ("authentication", "identity", "routing")}
    assert header_rules <= {f["rule_id"] for f in msg["findings"]}
    assert msg["summary"]["from"] == eml["summary"]["from"]


def test_sent_item_without_transport_headers():
    r = analyze_msg("outlook_sent_item.msg")
    f = rules(r)
    assert f["ESHA-901"]["severity"] == "info"
    assert f["ESHA-201"]["severity"] == "info", "no relay route is expected for a sent item"
    assert r["summary"]["from"]["address"] == "analyst@example.com"
    assert r["summary"]["subject"] == "Q3 report" and r["summary"]["date_utc"].startswith("2026-11-13T09:15")
    assert r["summary"]["message_id"] == "<sent.20261113.0915@example.com>"
    types = {a["filename"]: a["content_type"] for a in r["content"]["attachments"]}
    assert types["Q3_report.zip"] == "application/zip"
    assert types["Q3 figures (draft).msg"] == "message/rfc822"
    assert r["score"]["level"] == "low"


def test_rtf_only_body_is_reported():
    tree = make_samples.build_msg(subject="RTF", sender_name="A", sender_email="a@example.com", to="b@example.com")
    tree["__substg1.0_10090102"] = b"\x00" * 40  # compressed RTF only
    text, info = msg_to_eml(make_samples.write_cfb(tree))
    r = analyze(text, from_file=True, source=info)
    assert "ESHA-902" in rules(r)


@pytest.mark.parametrize("data", [
    b"not an ole file",
    make_samples.write_cfb({"WordDocument": b"x" * 100}),  # an OLE file that isn't a message
    (SAMPLES / "outlook_phish.msg").read_bytes()[:1500],  # truncated
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(range(256)) * 16,  # OLE magic followed by garbage
])
def test_bad_msg_files_raise_a_clear_error(data):
    with pytest.raises(MsgError):
        decode_bytes(data, "x.msg")


def test_random_ole_garbage_never_crashes():
    import random
    good = (SAMPLES / "outlook_phish.msg").read_bytes()
    rnd = random.Random(1234)
    for _ in range(60):
        data = bytearray(good)
        for _ in range(rnd.randint(1, 40)):
            data[rnd.randrange(512, len(data))] = rnd.randrange(256)
        try:
            text, info = msg_to_eml(bytes(data))
            analyze(text, from_file=True, source=info)
        except MsgError:
            pass


def test_api_accepts_msg_upload_and_raw_body():
    client = create_app().test_client()
    data = (SAMPLES / "outlook_phish.msg").read_bytes()
    resp = client.post("/api/analyze", data={"file": (io.BytesIO(data), "mail.msg")}, content_type="multipart/form-data")
    assert resp.status_code == 200 and resp.get_json()["meta"]["input"]["format"] == "msg"
    raw = client.post("/api/analyze", data=data, content_type="application/vnd.ms-outlook")
    assert raw.get_json()["score"]["level"] == "high"
    bad = client.post("/api/analyze", data={"file": (io.BytesIO(b"junk"), "mail.msg")}, content_type="multipart/form-data")
    assert bad.status_code == 400 and "Outlook" in bad.get_json()["error"]


def test_cli_reads_msg(capsys):
    assert main(["analyze", str(SAMPLES / "outlook_phish.msg"), "--no-color"]) == 2
    assert "Look-alike domain imitating PayPal" in capsys.readouterr().out
