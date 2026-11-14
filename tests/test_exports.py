"""IOC extraction and exports (CSV, JSON, STIX 2.1, MISP, HTML)."""
import csv
import io
import json
import re
from pathlib import Path

import pytest

from esha.__main__ import main
from esha.app import create_app
from esha.core import analyze
from esha.core.exports import ExportError, export
from esha.core.iocs import defang_email, defang_ip, defang_url

SAMPLES = Path(__file__).parent / "samples"


@pytest.fixture(scope="module")
def payroll():
    return analyze((SAMPLES / "esp_spoof_payload.eml").read_text(), from_file=True)


def test_defanging():
    assert defang_url("https://evil.example/a.b?x=1") == "hxxps[://]evil[.]example/a.b?x=1"
    assert defang_url("http://45.9.12.8/login") == "hxxp[://]45[.]9[.]12[.]8/login"
    assert defang_ip("1.2.3.4") == "1[.]2[.]3[.]4" and defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"
    assert defang_email("a.b@x.example") == "a.b[@]x[.]example"


def test_iocs_cover_sender_links_and_files(payroll):
    x = payroll["iocs"]
    ips = {i["value"]: i for i in x["ips"]}
    assert ips["73.15.22.9"]["roles"] == ["origin"] and ips["73.15.22.9"]["suspicious"]
    assert ips["45.9.12.8"]["roles"] == ["link"]
    doms = {d["value"]: d for d in x["domains"]}
    assert doms["acmecorp-hr.com"]["suspicious"] and "reply-to" in doms["acmecorp-hr.com"]["roles"]
    assert not doms["sendgrid.info"]["suspicious"]
    assert {u["host"] for u in x["urls"]} >= {"bit.ly", "acme-payroll-review.web.app"}
    assert x["files"][0]["sha256"] and len(x["files"][0]["md5"]) == 32
    assert "jane.doe@acme-corp.com" not in {e["value"] for e in x["emails"]}, "recipients are not indicators"


def test_hashes_are_correct():
    import hashlib
    r = analyze((SAMPLES / "iso_lnk.eml").read_text(), from_file=True)
    iso = (SAMPLES / "files" / "invoice_fixture.iso").read_bytes()
    f = r["iocs"]["files"][0]
    assert f["sha256"] == hashlib.sha256(iso).hexdigest() and "Invoice_Nov2026.lnk" in f["contains"]


def test_csv_export_and_formula_injection():
    r = analyze("From: a@example.com\nSubject: =HYPERLINK(\"http://x\")\nTo: b@example.com\n")
    content, media, name = export(r, "csv")
    assert media == "text/csv" and name.endswith("iocs.csv")
    rows = list(csv.reader(io.StringIO(content)))
    subject = next(row for row in rows if row[0] == "email-subject")
    assert subject[1].startswith("'="), "formulas from the message must not run in a spreadsheet"


def _stix_ids(bundle):
    return {o["id"] for o in bundle["objects"]}


def test_stix_bundle_is_well_formed(payroll):
    bundle = json.loads(export(payroll, "stix")[0])
    assert bundle["type"] == "bundle" and re.fullmatch(r"bundle--[0-9a-f-]{36}", bundle["id"])
    ids = _stix_ids(bundle)
    for o in bundle["objects"]:
        assert o["spec_version"] == "2.1" and o["id"].startswith(o["type"] + "--")
        if o["type"] in ("indicator", "report"):
            assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", o["created"])
        if o["type"] == "indicator":
            assert o["pattern_type"] == "stix" and re.fullmatch(r"\[[\w-]+:[\w.'-]+ = '.*'\]", o["pattern"])
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert set(report["object_refs"]) <= ids
    assert any(o["type"] == "indicator" and "acmecorp-hr.com" in o["pattern"] for o in bundle["objects"])
    assert not any(o["type"] == "indicator" and "sendgrid.info" in o["pattern"] for o in bundle["objects"]), \
        "benign infrastructure must not become an indicator"
    # deterministic: exporting again yields the same IDs
    assert _stix_ids(json.loads(export(payroll, "stix")[0])) == ids


def test_stix_pattern_escaping():
    from esha.core.exports import _pattern_value
    assert _pattern_value("a'b\\c") == "a\\'b\\\\c"


def test_misp_event(payroll):
    ev = json.loads(export(payroll, "misp")[0])["Event"]
    types = {a["type"] for a in ev["Attribute"]}
    assert {"ip-src", "ip-dst", "domain", "url", "email-src", "email-reply-to", "filename|sha256", "email-subject"} <= types
    assert ev["threat_level_id"] == "1" and {"name": "tlp:amber"} in ev["Tag"]
    flagged = [a for a in ev["Attribute"] if a["to_ids"]]
    assert flagged and all(a["value"] != "sendgrid.info" for a in flagged)


def test_html_report_is_inert_and_escaped():
    hostile = ('From: "<script>alert(1)</script>" <x@evil.example>\nSubject: <img src=x onerror=alert(1)>\n'
               "To: a@example.com\nContent-Type: text/html\n\n<a href=\"https://evil.example/p\">click</a>\n")
    page = export(analyze(hostile, from_file=True), "html")[0]
    assert "<script" not in page.lower() and "<img" not in page.lower()
    assert "&lt;script&gt;" in page and "default-src 'none'" in page
    assert "href=" not in page, "no live links in the report"
    assert "hxxps[://]evil[.]example/p" in page


def test_html_report_marks_slowest_hop():
    text = ("Received: from b by c; Fri, 13 Nov 2026 12:00:10 +0000\n"
            "Received: from a by b; Fri, 13 Nov 2026 10:00:00 +0000\n"
            "Received: from x by a; Fri, 13 Nov 2026 09:59:58 +0000\nFrom: a@example.com\n")
    page = export(analyze(text), "html")[0]
    assert '<td class="slowest">+2 h 10 s (slowest)</td>' in page
    assert page.count('<tr class="slow">') == 1


def test_unknown_format():
    with pytest.raises(ExportError):
        export({"summary": {}}, "pdf")


# ------------------------------------------------------------------ API
@pytest.fixture
def client():
    return create_app().test_client()


def test_api_analyze_with_format(client):
    resp = client.post("/api/analyze?format=misp", json={"headers": (SAMPLES / "phish_paypal.eml").read_text()})
    assert resp.status_code == 200 and "attachment" in resp.headers["Content-Disposition"]
    assert resp.get_json()["Event"]["Attribute"]


def test_api_export_roundtrip(client):
    report = client.post("/api/analyze", json={"headers": (SAMPLES / "phish_paypal.eml").read_text()}).get_json()
    assert "iocs" in report and report["summary"]["subject"]  # existing fields unchanged, iocs added
    resp = client.post("/api/export", json={"report": report, "format": "stix"})
    assert resp.status_code == 200 and resp.headers["Content-Type"].startswith("application/stix+json")
    assert client.post("/api/export", json={"report": report, "format": "exe"}).status_code == 400
    assert client.post("/api/export", json={"report": {"x": 1}, "format": "csv"}).status_code == 400


# ------------------------------------------------------------------ CLI
def test_cli_formats(tmp_path, capsys):
    out = tmp_path / "event.json"
    assert main(["analyze", str(SAMPLES / "phish_paypal.eml"), "-f", "misp", "-o", str(out)]) == 2
    assert json.loads(out.read_text())["Event"]["info"].startswith("ESHA:")
    assert main(["analyze", str(SAMPLES / "legit_github.eml"), "-f", "csv"]) == 0
    assert capsys.readouterr().out.startswith("type,value,defanged")
    assert main(["analyze", str(SAMPLES / "phish_paypal.eml"), "--json"]) == 0, "--json keeps exiting 0"
