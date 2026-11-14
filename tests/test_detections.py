"""Tests for the Phase 1 detections and the false-positive corpus."""
import time
from pathlib import Path

import pytest
from scripts_loader import make_samples

from esha.core import analyze
from esha.core.attachments import html_smuggling, inspect_container, parse_ics
from esha.core.esp import detect, esp_of_domain

SAMPLES = Path(__file__).parent / "samples"
FP = SAMPLES / "fp"


def report(name):
    return analyze((SAMPLES / name).read_text(), from_file=True)


def rules(r):
    return {f["rule_id"]: f for f in r["findings"]}


# ------------------------------------------------------- attack samples
@pytest.mark.parametrize("sample,expected,level", [
    ("html_smuggling.eml", {"ESHA-420"}, "high"),
    ("archive_payloads.eml", {"ESHA-421", "ESHA-422", "ESHA-423"}, "high"),
    ("iso_lnk.eml", {"ESHA-423", "ESHA-402"}, "high"),
    ("calendar_phish.eml", {"ESHA-424", "ESHA-425"}, "medium"),
    ("quishing.eml", {"ESHA-427", "ESHA-426", "ESHA-322"}, "high"),
    ("dkim_bimi_spoof.eml", {"ESHA-020", "ESHA-021", "ESHA-024"}, "high"),
    ("thread_hijack.eml", {"ESHA-324"}, "high"),
    ("bulk_no_unsubscribe.eml", {"ESHA-320", "ESHA-022"}, "low"),
])
def test_attack_samples_trigger_their_rules(sample, expected, level):
    r = report(sample)
    assert expected <= set(rules(r)), sorted(rules(r))
    assert r["score"]["level"] == level


def test_html_smuggling_details():
    f = rules(report("html_smuggling.eml"))["ESHA-420"]
    assert f["severity"] == "critical"
    assert "atob() base64 decoding" in f["detail"] and "large base64 blob" in f["detail"]
    assert any(a["id"] == "T1027.006" for a in f["attack"])


def test_archive_listing_and_password_hint():
    r = report("archive_payloads.eml")
    f = rules(r)
    assert "password" in f["ESHA-421"]["detail"].lower()
    assert "Invoice_88213.js" in f["ESHA-423"]["detail"]
    assert "Statement_Q4.zip" in f["ESHA-422"]["detail"]
    zips = {a["filename"]: a["container"] for a in r["content"]["attachments"]}
    assert zips["Invoice_88213.zip"]["encrypted"] and not zips["Statements.zip"]["encrypted"]


def test_iso_contents_are_listed_from_a_real_image():
    c = next(a["container"] for a in report("iso_lnk.eml")["content"]["attachments"] if a["extension"] == "iso")
    assert c["format"] == "ISO 9660" and c["listing"] == "complete"
    assert {"Invoice_Nov2026.lnk", "resources/updater.dll"} <= set(c["entries"])


def test_calendar_links_join_the_link_table():
    r = report("calendar_phish.eml")
    assert r["content"]["calendar"][0]["organizer"] == "hr-notice@benefits-update.example"
    hosts = {lk["host"] for lk in r["content"]["links"] if lk["source"].startswith("calendar")}
    assert hosts == {"benefits-update.example"}


def test_quishing_is_high_when_unauthenticated():
    f = rules(report("quishing.eml"))
    assert f["ESHA-427"]["severity"] == "high"


def test_thread_hijack_names_the_imitated_domain():
    assert "acme-corp.example" in rules(report("thread_hijack.eml"))["ESHA-324"]["detail"]


# ---------------------------------------------------- false positives
FP_SAMPLES = sorted(p.name for p in FP.glob("*.eml"))


def test_fp_corpus_is_not_empty():
    assert len(FP_SAMPLES) >= 8


@pytest.mark.parametrize("name", FP_SAMPLES)
def test_legitimate_mail_is_low_risk(name):
    r = analyze((FP / name).read_text(), from_file=True)
    risky = [(f["rule_id"], f["title"]) for f in r["findings"] if f["severity"] in ("critical", "high")]
    assert r["score"]["level"] == "low", (r["score"], risky)
    assert not risky


def test_clean_reference_sample_still_low():
    assert report("legit_github.eml")["score"]["level"] == "low"


@pytest.mark.parametrize("name,esp", [
    ("mailchimp_newsletter.eml", "Mailchimp"), ("sendgrid_receipt.eml", "SendGrid"),
    ("ses_password_reset.eml", "Amazon SES"), ("mailgun_notification.eml", "Mailgun"),
    ("sfmc_promo.eml", "Salesforce Marketing Cloud"),
])
def test_esps_are_recognised_and_explained(name, esp):
    r = analyze((FP / name).read_text(), from_file=True)
    assert r["summary"]["esp"]["name"] == esp
    for f in r["findings"]:
        if f["rule_id"] in ("ESHA-006", "ESHA-011"):
            assert f["severity"] == "info" and "expected" in f["detail"]


def test_esp_on_spoofed_mail_explains_why_the_pass_means_nothing():
    f = rules(report("esp_spoof_payload.eml"))["ESHA-006"]
    assert f["severity"] == "medium" and "anyone with a SendGrid account" in f["detail"]


def test_receiving_microsoft_365_is_not_mistaken_for_the_sender():
    assert report("o365_spoof.eml")["summary"]["esp"] is None


def test_newsletter_notes():
    r = analyze((FP / "mailchimp_newsletter.eml").read_text(), from_file=True)
    f = rules(r)
    assert f["ESHA-428"]["severity"] == "info" and "tracking pixel" in f["ESHA-428"]["detail"]
    assert f["ESHA-023"]["severity"] == "info"
    assert r["content"]["images"]["tracking_pixels"] == 1


def test_one_click_unsubscribe_note():
    assert "ESHA-321" in rules(analyze((FP / "sfmc_promo.eml").read_text(), from_file=True))
    assert "ESHA-321" not in rules(analyze((FP / "mailchimp_newsletter.eml").read_text(), from_file=True))


def test_thread_subject_note_on_notifications():
    assert rules(analyze((FP / "mailgun_notification.eml").read_text(), from_file=True))["ESHA-323"]["severity"] == "info"


# ------------------------------------------------------------- units
def test_smuggling_indicators():
    assert html_smuggling("<p>Hello, see our offers</p><script>console.log(1)</script>") == []
    hits = html_smuggling('<a id=x></a><script>x.href=URL.createObjectURL(new Blob([atob("QQ==")]));x.download="a.iso"</script>')
    assert {"atob() base64 decoding", "Blob built in the browser", "createObjectURL download link",
            "scripted download attribute"} <= set(hits)
    assert html_smuggling('<a href="data:application/octet-stream;base64,TVqQ">x</a>') == ["embedded file as data: URI"]


@pytest.mark.parametrize("text", ["a" * 4_000_000, ("a" * 8191 + " ") * 500, "atob(" * 200_000, "<" * 2_000_000])
def test_smuggling_scan_is_fast_on_hostile_input(text):
    t = time.perf_counter()
    html_smuggling(text)
    assert time.perf_counter() - t < 2


def test_zip_listing_flags_encryption_nesting_and_executables():
    z = make_samples.zip_bytes({"a/report.pdf.exe": b"x", "inner.7z": b"x", "notes.txt": b"x"}, encrypt=True)
    c = inspect_container(z, "zip")
    assert c["encrypted"] and c["listing"] == "complete"
    assert [r["name"] for r in c["risky"]] == ["a/report.pdf.exe"]
    assert c["nested"] == ["inner.7z"]


def test_office_documents_are_not_treated_as_archives():
    assert inspect_container(make_samples.zip_bytes({"word/document.xml": b"<w/>"}), "docx") is None


def test_unparsed_containers_get_a_name_scan():
    vhd = b"vhdxfile" + b"\x00" * 100 + "Payroll_Q4.lnk".encode("utf-16-le") + b"\x00" * 50 + b"setup.exe\x00"
    c = inspect_container(vhd, "vhdx")
    assert c["format"] == "VHDX" and c["listing"] == "names found in raw data"
    assert {"Payroll_Q4.lnk", "setup.exe"} <= {r["name"] for r in c["risky"]}
    rar = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 40 + b"invoice.js"
    assert inspect_container(rar, "rar")["format"] == "RAR"
    assert inspect_container(b"\x89PNG\r\n\x1a\n....", "png") is None


@pytest.mark.parametrize("data", [b"", b"PK\x03\x04garbage", b"CD001" * 1000, b"\x00" * 40000, b"Rar!\x1a\x07\x00\xff\xff"])
def test_container_parsers_survive_garbage(data):
    for ext in ("zip", "iso", "img", "rar", "vhd"):
        inspect_container(data, ext)


def test_ics_parser_unfolds_and_extracts():
    ics = parse_ics("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nORGANIZER;CN=\"A, B\":mailto:a@x.example\r\n"
                    "DESCRIPTION:Join https://meet.x.ex\r\n ample/abc\\nthanks\r\nSUMMARY:Sync\r\nEND:VEVENT\r\n")
    assert ics["method"] == "REQUEST" and ics["organizer"] == "a@x.example" and ics["summary"] == "Sync"
    assert ics["links"] == ["https://meet.x.example/abc"]


def test_esp_lookup():
    assert esp_of_domain("em123.sendgrid.net") == "SendGrid"
    assert esp_of_domain("example.com") is None
    assert detect({}, envelope="bounces@amazonses.com")["name"] == "Amazon SES"
    assert detect({}, relay_hosts=["mail-ed1-f44.google.com"]) is None  # one Google relay alone is not enough


def _hdr(extra, auth="dmarc=pass header.from=example.com"):
    return (f"Authentication-Results: mx.example.com; {auth}\n"
            "Received: from mx (mx [198.51.100.7]) by mx.example.com; Fri, 13 Nov 2026 10:00:00 +0000\n"
            "From: A <a@example.com>\nTo: b@example.com\nDate: Fri, 13 Nov 2026 10:00:00 +0000\n"
            "Message-ID: <1@example.com>\n" + extra)


@pytest.mark.parametrize("extra,rule,present", [
    ("Subject: RE: invoice\n", "ESHA-322", True),
    ("Subject: RE: invoice\nIn-Reply-To: <0@example.com>\n", "ESHA-322", False),
    ("Subject: [team] Re: plan\n", "ESHA-322", True),
    ("Subject: Weekly report\nReferences: <0@example.com>\n", "ESHA-323", True),
    ("Subject: Fwd: report\nReferences: <0@example.com>\n", "ESHA-323", False),
    ("Subject: x\nDKIM-Signature: v=1; d=example.com; s=a; h=to:subject:date; bh=x; b=y\n", "ESHA-020", True),
    ("Subject: x\nDKIM-Signature: v=1; d=example.com; s=a; h=from:to:subject:date:message-id; bh=x; b=y\n", "ESHA-020", False),
    ("Subject: x\nDKIM-Signature: v=1; d=example.com; s=a; l=0; h=from:to:subject:date; bh=x; b=y\n", "ESHA-021", True),
    ("Subject: x\nDKIM-Signature: v=1; d=example.com; s=a; h=from:to; bh=x; b=y\n", "ESHA-022", True),
    ("Subject: x\nBIMI-Indicator: PHN2Zz4=\n", "ESHA-023", True),
    ("Subject: x\nPrecedence: bulk\n", "ESHA-320", True),
    ("Subject: x\nPrecedence: bulk\nList-Unsubscribe: <mailto:u@example.com>\n", "ESHA-320", False),
])
def test_header_rules(extra, rule, present):
    assert (rule in rules(analyze(_hdr(extra)))) is present


def test_bimi_on_failing_dmarc():
    r = analyze(_hdr("Subject: x\nBIMI-Location: v=BIMI1; l=https://x.example/l.svg\n", "dmarc=fail header.from=example.com"))
    assert rules(r)["ESHA-024"]["severity"] == "medium"


def test_samples_are_reproducible(tmp_path, monkeypatch):
    """scripts/make_samples.py must regenerate exactly the committed samples."""
    monkeypatch.setattr(make_samples, "OUT", tmp_path)
    monkeypatch.setattr(make_samples, "FP", tmp_path / "fp")
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "invoice_fixture.iso").write_bytes((SAMPLES / "files" / "invoice_fixture.iso").read_bytes())
    monkeypatch.setattr(make_samples, "ROOT", tmp_path)
    make_samples.main()
    for f in sorted(tmp_path.rglob("*.eml")):
        assert f.read_text() == (SAMPLES / f.relative_to(tmp_path)).read_text(), f.name
