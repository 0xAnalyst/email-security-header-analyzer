from pathlib import Path

import pytest

from esha.app import create_app
from esha.core import analyze
from esha.core.auth import parse_authentication_results
from esha.core.domains import lookalike_brand, org_domain
from esha.core.received import build_hops, find_ips, parse_received

SAMPLES = Path(__file__).parent / "samples"


def load(name):
    return (SAMPLES / name).read_text()


def ids(report):
    return {f["title"] for f in report["findings"]}


# ---------------------------------------------------------------- received
def test_received_clauses_ignore_keywords_in_comments():
    h = parse_received("from mail.a.com (mail.a.com [8.8.8.8] (may be forged) by foo) "
                       "by mx.b.com with ESMTPS id 123 for <x@b.com>; Mon, 9 Nov 2026 10:00:00 +0000")
    assert h.from_host == "mail.a.com"
    assert h.by_host == "mx.b.com"
    assert h.protocol == "ESMTPS"
    assert h.from_ip == "8.8.8.8"
    assert h.for_addr == "x@b.com"
    assert h.tls


def test_ipv6_and_ipv4_extraction():
    ips = find_ips("from x ([IPv6:2001:4860:4864:20::22f]) (1.2.3.4) id 15.20.8137.20")
    assert "2001:4860:4864:20::22f" in ips and "1.2.3.4" in ips
    assert "15.20.8137.20" not in ips  # Exchange build numbers are not IPs


def test_clock_skew_is_not_reported_as_a_day_of_delay():
    hops = build_hops([
        "from c by a; Mon, 9 Nov 2026 10:00:00 +0000",   # newest
        "from a by b; Mon, 9 Nov 2026 10:00:10 +0000",   # oldest
    ])
    assert hops[1].delay == 0
    assert hops[1].clock_skew == -10


def test_mixed_naive_and_aware_timestamps_do_not_crash():
    report = analyze("Received: from a by b; Mon, 9 Nov 2026 10:00:05\n"
                     "Received: from c by a; Mon, 9 Nov 2026 10:00:03 +0000\nFrom: x@y.com\n")
    assert report["hops"][1]["delay"] == 2


def test_unparseable_date_does_not_crash():
    report = analyze("Received: from a by b; not a date\nFrom: x@y.com\n")
    assert report["hops"][0]["timestamp"] is None


# ------------------------------------------------------------------- auth
def test_authentication_results_parser():
    ar = parse_authentication_results(
        "mx.google.com; dkim=pass header.i=@github.com header.s=pf2023; "
        "spf=pass (google.com: ok) smtp.mailfrom=noreply@github.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com")
    assert ar["authserv_id"] == "mx.google.com"
    m = {r["method"]: r for r in ar["results"]}
    assert m["dkim"]["props"]["header.s"] == "pf2023"
    assert m["spf"]["props"]["smtp.mailfrom"] == "noreply@github.com"
    assert m["dmarc"]["props"]["policy.p"] == "REJECT"


def test_microsoft_authentication_results_without_authserv_id():
    ar = parse_authentication_results(
        "spf=fail (sender IP is 45.83.122.9) smtp.mailfrom=contoso.com; dkim=none (message not signed) "
        "header.d=none;dmarc=fail action=quarantine header.from=contoso.com;compauth=fail reason=000")
    m = {r["method"]: r for r in ar["results"]}
    assert m["spf"]["result"] == "fail"
    assert m["compauth"]["reason"] == "000"


def test_org_domain_uses_public_suffix_list():
    assert org_domain("mail.example.co.uk") == "example.co.uk"
    assert org_domain("a.b.github.com") == "github.com"


@pytest.mark.parametrize("domain,brand", [
    ("paypa1.com", "paypal"), ("rnicrosoft.com", "microsoft"), ("paypal-secure-login.net", "paypal"),
    ("arnazon.com", "amazon"),
])
def test_lookalikes(domain, brand):
    assert lookalike_brand(domain)["brand"] == brand


@pytest.mark.parametrize("domain", ["paypal.com", "amazonses.com", "github.com", "mail.microsoft.com", "example.org"])
def test_no_false_lookalikes(domain):
    assert lookalike_brand(domain) is None


# ---------------------------------------------------------------- samples
def test_legitimate_message_is_low_risk():
    r = analyze(load("legit_github.eml"), from_file=True)
    assert r["score"]["level"] == "low"
    assert r["auth"]["dmarc"]["result"] == "pass"
    assert r["auth"]["dkim"]["aligned"] and r["auth"]["spf"]["aligned"]
    assert r["origin"]["ip"] == "192.30.252.201"
    assert len(r["hops"]) == 3
    # body text must never be parsed as headers
    assert all(h["name"] != "Hey there! This is the body and must be ignored" for h in r["headers"])


def test_lookalike_phish_is_high_risk():
    r = analyze(load("phish_paypal.eml"), from_file=True)
    assert r["score"]["level"] == "high"
    t = ids(r)
    assert "Look-alike domain imitating PayPal" in t
    assert "Display name contains a different email address" in t
    assert "Reply-To differs from From" in t
    assert r["summary"]["subject"].startswith("Urgent")  # RFC 2047 decoded


def test_o365_spoof_is_high_risk():
    r = analyze(load("o365_spoof.eml"), from_file=True)
    assert r["score"]["level"] == "high"
    assert r["auth"]["compauth"]["result"] == "fail"
    assert r["spam"]["microsoft"]["CAT"] == "SPOOF"
    assert "Display name claims to be Microsoft" in ids(r)


def test_messy_outlook_paste():
    r = analyze(load("messy_paste.txt"))
    assert len(r["hops"]) == 3, "blank lines between pasted headers must be tolerated"
    assert r["summary"]["from"]["address"] == "billing@partner.example"
    assert any(h["clock_skew"] for h in r["hops"])


def test_empty_input():
    r = analyze("")
    assert r["score"]["level"] == "none"


# -------------------------------------------------------------------- web
@pytest.fixture
def client():
    return create_app().test_client()


def test_index_has_security_headers(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_api_json(client):
    resp = client.post("/api/analyze", json={"headers": load("phish_paypal.eml")})
    assert resp.status_code == 200
    assert resp.get_json()["score"]["level"] == "high"


def test_api_file_upload(client):
    import io
    data = {"file": (io.BytesIO(load("legit_github.eml").encode()), "msg.eml")}
    resp = client.post("/api/analyze", data=data, content_type="multipart/form-data")
    assert resp.get_json()["auth"]["dmarc"]["result"] == "pass"


def test_api_rejects_empty(client):
    assert client.post("/api/analyze", json={"headers": "  "}).status_code == 400


def test_api_raw_text_body(client):
    resp = client.post("/api/analyze", data=load("o365_spoof.eml"), content_type="text/plain")
    assert resp.status_code == 200


def test_health(client):
    assert client.get("/api/health").get_json()["status"] == "ok"


# ------------------------------------------------------- mismatches + content
def test_esp_spoof_with_payload():
    r = analyze(load("esp_spoof_payload.eml"), from_file=True)
    t = ids(r)
    assert r["score"]["level"] == "high"
    assert "SPF passed for a different domain" in t
    assert "DKIM signed by a different domain" in t
    assert "Authentication-Results from an unexpected server" in t
    assert "Reply-To imitates the sender's domain" in t
    assert "Sent from a residential or dynamic IP" in t
    assert "Disguised attachment" in t
    assert "Message contains a login or data form" in t
    assert "Link text does not match where it goes" in t
    rows = {a["label"]: a for a in r["auth"]["alignment"]}
    assert rows["SPF envelope sender"]["aligned"] is False
    assert rows["DKIM signer (d=)"]["domain"] == "sendgrid.info"
    hosts = {lk["host"] for lk in r["content"]["links"]}
    assert {"45.9.12.8", "bit.ly", "acme-payroll-review.web.app"} <= hosts


def test_legit_alignment_rows_are_aligned():
    r = analyze(load("legit_github.eml"), from_file=True)
    rows = [a for a in r["auth"]["alignment"] if a["label"] in ("SPF envelope sender", "DKIM signer (d=)", "Return-Path")]
    assert rows and all(a["aligned"] for a in rows)


def test_headers_only_has_no_content_section():
    assert analyze(load("o365_spoof.eml"), from_file=True)["content"] is None


@pytest.mark.parametrize("cand,ref,expected", [
    ("acmecorp-hr.com", "acme-corp.com", True),
    ("acme-c0rp.com", "acme-corp.com", True),
    ("acme-corp.net", "acme-corp.com", True),
    ("mail.acme-corp.com", "acme-corp.com", False),
    ("sendgrid.net", "acme-corp.com", False),
    ("gmail.com", "gmail.com", False),
])
def test_cousin_domains(cand, ref, expected):
    from esha.core.domains import cousin_domain
    assert cousin_domain(cand, ref) is expected


def test_link_text_mismatch_flag():
    from esha.core.body import _link_flags
    flags = _link_flags("https://evil.example/x", "https://www.paypal.com/signin", "paypal.com")
    assert any(f.startswith("text shows www.paypal.com") for f in flags)
    assert _link_flags("https://www.paypal.com/x", "www.paypal.com", "paypal.com") == []


def test_cyrillic_homoglyph_sender():
    r = analyze('From: "PayPal" <service@раураl.com>\nTo: a@b.com\nSubject: hi\n')
    assert any(f["title"] == "Look-alike domain imitating PayPal" and f["severity"] == "critical" for f in r["findings"])


# ------------------------------------------------------------ static site
def _load_build_site():
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_site", Path(__file__).parent.parent / "scripts" / "build_site.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_static_site_page_runs_in_browser_with_strict_csp():
    html = _load_build_site().render_index()
    assert '<meta name="esha-engine" content="browser">' in html
    assert "connect-src 'self'" in html and "script-src 'self' 'wasm-unsafe-eval'" in html
    assert '"/static/' not in html, "static URLs must be relative so the site works under /<repo>/"
    assert "never uploaded" in html


def test_server_page_uses_server_engine(client):
    html = client.get("/").get_data(as_text=True)
    assert '<meta name="esha-engine" content="server">' in html
    assert "wasm-unsafe-eval" not in html


def test_static_bundle_contains_engine_and_pure_python_deps(tmp_path):
    import zipfile
    dest = tmp_path / "bundle.zip"
    _load_build_site().build_bundle(dest)
    names = set(zipfile.ZipFile(dest).namelist())
    assert {"esha/core/analyzer.py", "esha/static/data/GeoLite2-Country.mmdb", "maxminddb/reader.py",
            "publicsuffixlist/__init__.py", "dateutil/parser/__init__.py"} <= names
    assert not any(n.endswith((".so", ".pyd", ".pyc")) for n in names), "the browser cannot load native extensions"
    assert not any(n.startswith(("esha/app", "flask/")) for n in names)


def test_fake_list_id_does_not_soften_reply_to_on_spoofed_mail():
    text = ("Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=bank.example; dmarc=fail header.from=bank.example\n"
            "Received: from x (x [198.51.100.7]) by mx.example.com; Fri, 13 Nov 2026 10:00:00 +0000\n"
            "From: Bank <alerts@bank.example>\nReply-To: claims@attacker.example\nList-Id: <news.attacker.example>\n"
            "To: a@example.com\nSubject: hi\nDate: Fri, 13 Nov 2026 10:00:00 +0000\nMessage-ID: <1@bank.example>\n")
    f = next(f for f in analyze(text)["findings"] if f["rule_id"] == "ESHA-108")
    assert f["severity"] == "medium"


def test_web_samples_match_test_samples():
    web = Path(__file__).parent.parent / "esha" / "static" / "samples"
    for f in list(web.glob("*.eml")) + list(web.glob("*.msg")):
        assert f.read_bytes() == (SAMPLES / f.name).read_bytes(), f"{f.name} differs from tests/samples"


def test_footer_credits_mha_and_links_source(client):
    html = client.get("/").get_data(as_text=True)
    assert "MHA by lnxg33k" in html and "GPL-3.0" in html
    assert 'href="https://github.com/0xAnalyst/email-security-header-analyzer">Source code</a>' in html
