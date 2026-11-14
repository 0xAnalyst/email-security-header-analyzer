#!/usr/bin/env python3
"""Regenerate the synthetic samples in tests/samples (detections) and
tests/samples/fp (false-positive corpus).

All names, domains and addresses are invented (example.* and *.example
domains), and IP addresses belong to the mail providers' published sending
ranges. Attachments are inert: the "LNK", "DLL" and "JS" payloads are short
text strings, and the ISO in tests/samples/files was made with
`hdiutil makehybrid -iso -joliet` and trimmed to its directory sectors.

    python scripts/make_samples.py
"""
from __future__ import annotations

import base64
import io
import struct
import zipfile
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "samples"
FP = OUT / "fp"
ANALYST = "analyst@example.com"

# A 1x1 transparent PNG and a small "QR-like" PNG (a 21x21 black/white grid, not a real QR code).
PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")


def qr_like_png() -> bytes:
    import zlib
    size, scale = 21, 4
    rows = []
    for y in range(size * scale):
        row = bytearray([0])
        for x in range(size * scale):
            cx, cy = x // scale, y // scale
            finder = any(cx - ox in range(7) and cy - oy in range(7) and
                         (cx - ox in (0, 6) or cy - oy in (0, 6) or (2 <= cx - ox <= 4 and 2 <= cy - oy <= 4))
                         for ox, oy in ((0, 0), (14, 0), (0, 14)))
            noise = (cx * 7 + cy * 13 + cx * cy) % 3 == 0 and not any(
                cx - ox in range(8) and cy - oy in range(8) for ox, oy in ((0, 0), (13, 0), (0, 13)))
            row.append(0 if finder or noise else 255)
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    w = h = size * scale
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def dkim(d, s, h, length=None, t=1794650000):
    return (f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={d}; s={s}; t={t};\n"
            f"        h={h};{f' l={length};' if length else ''}\n"
            f"        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\n"
            f"        b=eS1TaGEtc3ludGhldGljLXNpZ25hdHVyZS1mb3ItdGVzdHMtb25seQ==")


def gmail(*, origin_host, ip, mailfrom, ar, date, extra_hops=(), dkim_sigs=(), arc=None, rcpt=ANALYST):
    """Headers added on the way to a Gmail mailbox, newest first."""
    out = [("Delivered-To", rcpt),
           ("Received", f"by 2002:a05:7300:9c11:b0:12f:3a51:77e2 with SMTP id r17csp551201dyb;\n        {date}")]
    if arc:
        out += [("ARC-Seal", f"i=1; a=rsa-sha256; t=1794650000; cv={arc}; d=google.com; s=arc-20240605; b=c2VhbA=="),
                ("ARC-Authentication-Results", "i=1; mx.google.com;\n       " + ar)]
    out += [("Return-Path", f"<{mailfrom}>"),
            ("Received", f"from {origin_host} ({origin_host}. [{ip}])\n        by mx.google.com with ESMTPS id "
                         f"5b1f17b1804b1-43a1c2d3e4fsi118842f8f.211.2026.11.13\n        for <{rcpt}>\n"
                         f"        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);\n        {date}"),
            ("Received-SPF", f"pass (google.com: domain of {mailfrom} designates {ip} as permitted sender) client-ip={ip};"),
            ("Authentication-Results", "mx.google.com;\n       " + ar)]
    out += list(extra_hops)
    out += [("DKIM-Signature", sig) for sig in dkim_sigs]
    return out


def write(path: Path, headers, mime) -> None:
    body = mime.as_string() if mime is not None else ""
    head = "".join(f"{k}: {v}\n" for k, v in headers)
    path.write_text(head + body if body else head, encoding="utf-8")
    print("wrote", path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)


def multipart(parts, subtype="mixed", boundary="esha-sample-boundary"):
    m = MIMEMultipart(subtype, boundary=boundary)
    for p in parts:
        m.attach(p)
    return m


def alt(text, html, boundary="esha-alt-boundary"):
    return multipart([MIMEText(text, "plain", "utf-8"), MIMEText(html, "html", "utf-8")], "alternative", boundary)


def attach(data: bytes, filename: str, maintype="application", subtype="octet-stream"):
    part = MIMEApplication(data, subtype, Name=filename) if maintype == "application" else MIMEBase(maintype, subtype)
    if maintype != "application":
        part.set_payload(base64.b64encode(data).decode())
        part["Content-Transfer-Encoding"] = "base64"
    part.add_header("Content-Disposition", "attachment", filename=filename)
    return part


def zip_bytes(files: dict[str, bytes], encrypt=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 13, 9, 0, 0))
            zf.writestr(info, data)
    data = bytearray(buf.getvalue())
    if encrypt:  # set the "encrypted" flag in local and central headers (ZipCrypto marker only)
        i = 0
        while (i := data.find(b"PK\x03\x04", i)) != -1:
            data[i + 6] |= 0x01
            i += 4
        i = 0
        while (i := data.find(b"PK\x01\x02", i)) != -1:
            data[i + 8] |= 0x01
            i += 4
    return bytes(data)


# ===================================================================== attacks
def html_smuggling():
    blob = base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(9000))).decode()
    page = f"""<!doctype html><html><head><title>Secure Document</title></head><body>
<p>Loading your secure document...</p>
<script>
var d = "{blob}";
var b = atob(d), a = new Uint8Array(b.length);
for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
var f = new Blob([a], {{type: "application/octet-stream"}});
if (window.navigator.msSaveOrOpenBlob) {{ window.navigator.msSaveOrOpenBlob(f, "Remittance_Advice.iso"); }}
else {{ var l = document.createElement("a"); l.href = URL.createObjectURL(f); l.download = "Remittance_Advice.iso"; l.click(); }}
</script></body></html>"""
    date = "Fri, 13 Nov 2026 08:41:19 -0800 (PST)"
    h = gmail(origin_host="mail.contoso-billing.example", ip="185.234.72.19", mailfrom="ap@contoso-billing.example",
              date=date, ar="spf=pass (google.com: domain of ap@contoso-billing.example designates 185.234.72.19 as permitted sender) "
                            "smtp.mailfrom=ap@contoso-billing.example;\n       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=fabrikam.example")
    h += [("From", "Fabrikam Accounts Payable <ap@fabrikam.example>"), ("To", ANALYST),
          ("Subject", "Remittance advice 2026-11-13"), ("Date", "Fri, 13 Nov 2026 16:40:02 +0000"),
          ("Message-ID", "<20261113164002.7781@contoso-billing.example>")]
    m = multipart([MIMEText("Please find the remittance advice attached. Open it in your browser to view.", "plain", "utf-8"),
                   attach(page.encode(), "Remittance_Advice.html", "text", "html")])
    write(OUT / "html_smuggling.eml", h, m)


def archive_payloads():
    inner = zip_bytes({"Statement_Q4.zip": zip_bytes({"Statement_Q4.pdf.js": b"// ESHA inert test fixture\n"})})
    locked = zip_bytes({"Invoice_88213.js": b"// ESHA inert test fixture\n", "readme.txt": b"see invoice"}, encrypt=True)
    date = "Fri, 13 Nov 2026 07:12:44 -0800 (PST)"
    h = gmail(origin_host="vps-2291.hosting.example", ip="45.141.84.120", mailfrom="billing@invoices-portal.example",
              date=date, ar="spf=softfail (google.com: domain of transitioning billing@invoices-portal.example does not designate "
                            "45.141.84.120 as permitted sender) smtp.mailfrom=billing@invoices-portal.example;\n"
                            "       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=invoices-portal.example")
    h += [("From", "Billing Department <billing@invoices-portal.example>"), ("To", ANALYST),
          ("Subject", "Invoice 88213 overdue"), ("Date", "Fri, 13 Nov 2026 15:11:58 +0000"),
          ("Message-ID", "<5f2e1c9a.88213@invoices-portal.example>")]
    m = multipart([MIMEText("Hello,\n\nYour invoice is overdue. The documents are attached.\n\n"
                            "Archive password: 88213\n\nBilling Department", "plain", "utf-8"),
                   attach(locked, "Invoice_88213.zip", "application", "zip"),
                   attach(inner, "Statements.zip", "application", "zip")])
    write(OUT / "archive_payloads.eml", h, m)


def iso_lnk():
    iso = (OUT / "files" / "invoice_fixture.iso").read_bytes()
    date = "Thu, 12 Nov 2026 23:05:31 -0800 (PST)"
    h = gmail(origin_host="smtp.freight-docs.example", ip="91.92.243.17", mailfrom="docs@freight-docs.example", date=date,
              ar="spf=pass (google.com: domain of docs@freight-docs.example designates 91.92.243.17 as permitted sender) "
                 "smtp.mailfrom=docs@freight-docs.example;\n       dkim=pass header.i=@freight-docs.example header.s=default;\n"
                 "       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=freight-docs.example",
              dkim_sigs=[dkim("freight-docs.example", "default", "from:to:subject:date:message-id")])
    h += [("From", "Shipping Documents <docs@freight-docs.example>"), ("To", ANALYST),
          ("Subject", "Shipment documents and invoice"), ("Date", "Fri, 13 Nov 2026 07:04:12 +0000"),
          ("Message-ID", "<shipment.20261113.0412@freight-docs.example>")]
    m = multipart([MIMEText("Dear customer,\n\nThe shipping documents for your order are attached as a disk image.\n",
                            "plain", "utf-8"),
                   attach(iso, "Invoice_Nov2026.iso", "application", "x-iso9660-image")])
    write(OUT / "iso_lnk.eml", h, m)


def calendar_phish():
    ics = "\r\n".join([
        "BEGIN:VCALENDAR", "PRODID:-//ESHA//sample//EN", "VERSION:2.0", "METHOD:REQUEST", "BEGIN:VEVENT",
        "DTSTART:20261116T090000Z", "DTEND:20261116T093000Z", "DTSTAMP:20261113T100000Z",
        "ORGANIZER;CN=HR Department:mailto:hr-notice@benefits-update.example",
        "UID:7f3c1e2a-9b44-4d1e-8a21-2f6c0e9d1b77@benefits-update.example",
        "ATTENDEE;CN=Analyst;ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:analyst@example.com",
        "SUMMARY:Mandatory: 2027 benefits enrolment",
        "DESCRIPTION:Your benefits selection expires Monday. Review and sign here: https://benefits-update.example/s",
        " ign?u=analyst\\nQuestions? Reply to HR.",
        "LOCATION:https://benefits-update.example/meet",
        "STATUS:CONFIRMED", "END:VEVENT", "END:VCALENDAR", ""])
    date = "Fri, 13 Nov 2026 02:00:41 -0800 (PST)"
    h = gmail(origin_host="mail-relay.example-hr.example", ip="194.180.48.33", mailfrom="bounce@example-hr.example", date=date,
              ar="spf=pass (google.com: domain of bounce@example-hr.example designates 194.180.48.33 as permitted sender) "
                 "smtp.mailfrom=bounce@example-hr.example;\n       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=example.com")
    h += [("From", "HR Department <hr@example.com>"), ("To", ANALYST),
          ("Subject", "Invitation: Mandatory: 2027 benefits enrolment @ Mon 16 Nov 2026 09:00 (UTC)"),
          ("Date", "Fri, 13 Nov 2026 10:00:02 +0000"), ("Message-ID", "<invite.7f3c1e2a@example-hr.example>")]
    cal = MIMEText(ics, "calendar", "utf-8")
    cal.set_param("method", "REQUEST")
    m = multipart([MIMEText("You have been invited to: Mandatory: 2027 benefits enrolment", "plain", "utf-8"), cal],
                  "alternative")
    write(OUT / "calendar_phish.eml", h, m)


def quishing():
    html = ('<html><body><p>Re-authenticate MFA</p><img src="cid:qr001" width="300" height="300" alt="">'
            '<p>Scan the QR code with your phone.</p></body></html>')
    h = [("Received", "from AM9PR04MB7709.eurprd04.prod.outlook.com (2603:10a6:20b:3d1::19) by\n"
                      " PA4PR04MB9222.eurprd04.prod.outlook.com with HTTPS; Fri, 13 Nov 2026 13:31:08 +0000"),
         ("Authentication-Results", "spf=softfail (sender IP is 103.151.172.66)\n smtp.mailfrom=it-helpdesk.example; "
                                    "dkim=none (message not signed)\n header.d=none;dmarc=fail action=none\n"
                                    " header.from=example.com;compauth=fail reason=601"),
         ("Received-SPF", "SoftFail (protection.outlook.com: domain of transitioning\n it-helpdesk.example discourages "
                          "use of 103.151.172.66 as permitted sender)"),
         ("Received", "from host-103-151-172-66.static.example (103.151.172.66) by\n"
                      " AM9PR04MB7709.mail.protection.outlook.com (10.167.242.68) with Microsoft SMTP Server\n"
                      " (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8137.20;\n"
                      " Fri, 13 Nov 2026 13:31:07 +0000"),
         ("From", "IT Service Desk <servicedesk@example.com>"), ("To", ANALYST),
         ("Subject", "RE: Action required: MFA re-registration"),
         ("Date", "Fri, 13 Nov 2026 13:30:51 +0000"), ("Message-ID", "<qr.20261113133051@it-helpdesk.example>")]
    img = MIMEImage(qr_like_png(), "png")
    img.add_header("Content-ID", "<qr001>")
    img.add_header("Content-Disposition", "inline", filename="qr.png")
    m = multipart([alt("Re-authenticate MFA. Scan the QR code with your phone.", html), img], "related")
    write(OUT / "quishing.eml", h, m)


def dkim_bimi_spoof():
    date = "Fri, 13 Nov 2026 03:22:10 -0800 (PST)"
    h = gmail(origin_host="mta7.bulk-sender.example", ip="5.188.206.14", mailfrom="news@bulk-sender.example", date=date,
              ar="dkim=pass header.i=@bulk-sender.example header.s=k1 header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of news@bulk-sender.example designates 5.188.206.14 as permitted sender) "
                 "smtp.mailfrom=news@bulk-sender.example;\n       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=example.net",
              dkim_sigs=[dkim("bulk-sender.example", "k1", "to:date:message-id", length="120")])
    h += [("BIMI-Location", "v=BIMI1; l=https://bulk-sender.example/brand/logo.svg"),
          ("BIMI-Indicator", "PHN2ZyB2ZXJzaW9uPSIxLjIiIGJhc2VQcm9maWxlPSJ0aW55LXBzIj48L3N2Zz4="),
          ("From", "Example Bank Security <security@example.net>"), ("To", ANALYST),
          ("Subject", "Your statement is ready"), ("Date", "Fri, 13 Nov 2026 11:21:40 +0000"),
          ("Message-ID", "<stmt.4471@bulk-sender.example>")]
    m = MIMEText("Your monthly statement is ready to view online.", "plain", "utf-8")
    write(OUT / "dkim_bimi_spoof.eml", h, m)


def thread_hijack():
    date = "Fri, 13 Nov 2026 09:47:02 -0800 (PST)"
    h = gmail(origin_host="mail.acme-c0rp.example", ip="193.42.33.101", mailfrom="j.smith@acme-c0rp.example", date=date,
              ar="dkim=pass header.i=@acme-c0rp.example header.s=s1 header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of j.smith@acme-c0rp.example designates 193.42.33.101 as permitted sender) "
                 "smtp.mailfrom=j.smith@acme-c0rp.example;\n       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=acme-c0rp.example",
              dkim_sigs=[dkim("acme-c0rp.example", "s1", "from:to:cc:subject:date:message-id:in-reply-to:references")])
    h += [("From", "John Smith <j.smith@acme-c0rp.example>"), ("To", "Analyst <analyst@example.com>"),
          ("Cc", "Accounts <accounts@acme-corp.example>"),
          ("Subject", "RE: Updated bank details for Q4 payments"), ("Date", "Fri, 13 Nov 2026 17:46:40 +0000"),
          ("Message-ID", "<CAF4x9.20261113174640@acme-c0rp.example>"),
          ("In-Reply-To", "<9f81c2.20261112@mail.acme-corp.example>"),
          ("References", "<77ab01.20261110@mail.acme-corp.example>\n <9f81c2.20261112@mail.acme-corp.example>")]
    m = MIMEText("Hi,\n\nAs discussed, please use our new bank details for the Q4 payments from today.\n\nThanks,\nJohn",
                 "plain", "utf-8")
    write(OUT / "thread_hijack.eml", h, m)


def bulk_no_unsubscribe():
    date = "Fri, 13 Nov 2026 01:03:55 -0800 (PST)"
    h = gmail(origin_host="out3.promo-blast.example", ip="80.94.95.201", mailfrom="offers@promo-blast.example", date=date,
              ar="dkim=pass header.i=@promo-blast.example header.s=m1 header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of offers@promo-blast.example designates 80.94.95.201 as permitted sender) "
                 "smtp.mailfrom=offers@promo-blast.example;\n       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=promo-blast.example",
              dkim_sigs=[dkim("promo-blast.example", "m1", "from:to:date")])
    h += [("From", "Deals <offers@promo-blast.example>"), ("To", ANALYST), ("Subject", "Final hours: 80% off everything"),
          ("Date", "Fri, 13 Nov 2026 09:03:30 +0000"), ("Message-ID", "<blast.991@promo-blast.example>"),
          ("Precedence", "bulk"), ("List-Id", "Deals <deals.promo-blast.example>")]
    m = alt("Final hours: 80% off everything. https://promo-blast.example/sale",
            '<p>Final hours: <a href="https://promo-blast.example/sale">80% off everything</a></p>')
    write(OUT / "bulk_no_unsubscribe.eml", h, m)


# ===================================================== false-positive corpus
def _newsletter_html(shop, pixel_host, extra=""):
    return (f'<html><body><img src="https://{pixel_host}/logo.png" width="180" height="40" alt="{shop}">'
            f'<h1>New this week</h1><p>Hello, here is what is new in the {shop} catalogue this week: winter jackets, '
            f'trail shoes and a guide to layering for cold mornings. Members get free returns until the end of the month, '
            f'and our stores now open at nine on weekends.</p>'
            f'<p><a href="https://{pixel_host}/track/click?u=1">Shop the collection</a></p>{extra}'
            f'<p><a href="https://{pixel_host}/unsubscribe?u=1">Unsubscribe</a></p>'
            f'<img src="https://{pixel_host}/track/open.php?u=1" width="1" height="1" alt=""></body></html>')


def fp_mailchimp():
    date = "Thu, 12 Nov 2026 16:02:12 -0800 (PST)"
    h = gmail(origin_host="mail162.suw121.mcdlv.net", ip="198.2.162.17", mailfrom="bounce-mc.us21_1234567.4471-analyst=example.com@mail162.suw121.mcdlv.net",
              date=date, ar="dkim=pass header.i=@northwind.example header.s=k2 header.b=dGVzdA==;\n"
                            "       dkim=pass header.i=@mcdlv.net header.s=k3 header.b=dGVzdA==;\n"
                            "       spf=pass (google.com: domain of bounce-mc.us21_1234567.4471-analyst=example.com@mail162.suw121.mcdlv.net "
                            "designates 198.2.162.17 as permitted sender) smtp.mailfrom=\"bounce-mc.us21_1234567.4471-analyst=example.com@mail162.suw121.mcdlv.net\";\n"
                            "       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=northwind.example",
              dkim_sigs=[dkim("northwind.example", "k2", "subject:from:reply-to:to:date:message-id:list-id:list-unsubscribe:list-unsubscribe-post:content-type:mime-version"),
                         dkim("mcdlv.net", "k3", "subject:from:reply-to:to:date:message-id:list-id:list-unsubscribe:list-unsubscribe-post:content-type:mime-version")])
    h += [("BIMI-Location", "v=BIMI1; l=https://northwind.example/bimi/logo.svg"),
          ("BIMI-Indicator", "PHN2ZyB2ZXJzaW9uPSIxLjIiIGJhc2VQcm9maWxlPSJ0aW55LXBzIj48L3N2Zz4="),
          ("From", "Northwind Outfitters <news@northwind.example>"), ("Reply-To", "Northwind Outfitters <hello@northwind.example>"),
          ("To", "<analyst@example.com>"), ("Subject", "New this week: winter jackets and trail shoes"),
          ("Date", "Fri, 13 Nov 2026 00:02:09 +0000"), ("Message-ID", "<a1b2c3d4e5.4471@mail162.suw121.mcdlv.net>"),
          ("List-Id", "1234567 mc list <1234567.xt.local>"),
          ("List-Unsubscribe", "<https://northwind.us21.list-manage.com/unsubscribe?u=1&id=2>, <mailto:unsubscribe-mc.us21_1234567@unsubscribe.mailchimp.com>"),
          ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"), ("X-MC-User", "1234567"), ("Precedence", "bulk"),
          ("Feedback-ID", "21:21.1234567:us21:mc")]
    m = alt("New this week at Northwind Outfitters: winter jackets, trail shoes and a layering guide. "
            "https://northwind.us21.list-manage.com/track/click?u=1",
            _newsletter_html("Northwind Outfitters", "northwind.us21.list-manage.com"))
    write(FP / "mailchimp_newsletter.eml", h, m)


def fp_sendgrid_receipt():
    date = "Fri, 13 Nov 2026 06:14:55 -0800 (PST)"
    mf = "bounces+1849502-ab12-analyst=example.com@em7781.tailspin.example"
    h = gmail(origin_host="o1.ptr7781.tailspin.example", ip="167.89.101.44", mailfrom=mf, date=date,
              ar="dkim=pass header.i=@tailspin.example header.s=s1 header.b=dGVzdA==;\n"
                 "       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=dGVzdA==;\n"
                 f"       spf=pass (google.com: domain of {mf} designates 167.89.101.44 as permitted sender) smtp.mailfrom=\"{mf}\";\n"
                 "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=tailspin.example",
              dkim_sigs=[dkim("tailspin.example", "s1", "from:subject:mime-version:to:cc:content-type:date:message-id"),
                         dkim("sendgrid.info", "smtpapi", "from:subject:mime-version:to:cc:content-type:date:message-id")])
    h += [("From", "Tailspin Toys <orders@tailspin.example>"), ("To", ANALYST), ("Subject", "Your order #44190 has shipped"),
          ("Date", "Fri, 13 Nov 2026 14:14:52 +0000"), ("Message-ID", "<Xk2p9Q7rS0eB1a2c3d4e5f@geopod-ismtpd-12>"),
          ("X-SG-EID", "u001.ZXNoYS1zYW1wbGU="), ("X-Entity-ID", "u001.ZXNoYQ==")]
    m = alt("Hi, your order #44190 has shipped and should arrive on Tuesday. Track it at "
            "https://www.tailspin.example/orders/44190. Thanks for shopping with Tailspin Toys.",
            '<p>Hi, your order #44190 has shipped and should arrive on Tuesday. Your parcel contains two items, and '
            'the courier will leave it with a neighbour if you are out.</p><p><a href="https://www.tailspin.example/orders/44190">'
            'Track your order</a></p><p>Thanks for shopping with Tailspin Toys.</p>'
            '<img src="https://u1849502.ct.sendgrid.net/wf/open?upn=abc" width="1" height="1" alt="" style="height:1px!important">')
    write(FP / "sendgrid_receipt.eml", h, m)


def fp_ses_reset():
    date = "Fri, 13 Nov 2026 04:55:30 -0800 (PST)"
    mf = "010001934f1e2a3b-6c8d2e11-aaaa-4b1e-9e77-1f2a3b4c5d6e-000000@amazonses.com"
    h = gmail(origin_host="a8-31.smtp-out.amazonses.com", ip="54.240.8.31", mailfrom=mf, date=date,
              ar="dkim=pass header.i=@fabrikam.example header.s=ug7nbtf4gccmlpwj322ax3p6ow6yfsug header.b=dGVzdA==;\n"
                 "       dkim=pass header.i=@amazonses.com header.s=224i4yxa5dv7c2xz3womw6peuasteono header.b=dGVzdA==;\n"
                 f"       spf=pass (google.com: domain of {mf} designates 54.240.8.31 as permitted sender) smtp.mailfrom={mf};\n"
                 "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=fabrikam.example",
              dkim_sigs=[dkim("fabrikam.example", "ug7nbtf4gccmlpwj322ax3p6ow6yfsug",
                              "Content-Type:From:To:Subject:Message-ID:Content-Transfer-Encoding:Date:MIME-Version"),
                         dkim("amazonses.com", "224i4yxa5dv7c2xz3womw6peuasteono",
                              "Content-Type:From:To:Subject:Message-ID:Content-Transfer-Encoding:Date:MIME-Version:Feedback-ID")])
    h += [("From", "Fabrikam <no-reply@fabrikam.example>"), ("To", ANALYST), ("Subject", "Reset your Fabrikam password"),
          ("Date", "Fri, 13 Nov 2026 12:55:29 +0000"),
          ("Message-ID", "<010001934f1e2a3b-6c8d2e11-aaaa-4b1e-9e77-1f2a3b4c5d6e-000000@email.amazonses.com>"),
          ("Feedback-ID", "1.us-east-1.abcdefghijklmnop=:AmazonSES"), ("X-SES-Outgoing", "2026.11.13-54.240.8.31")]
    m = MIMEText("Hi,\n\nWe received a request to reset the password for your Fabrikam account. If this was you, use the "
                 "link below within 30 minutes:\n\nhttps://account.fabrikam.example/reset?token=Zm9vYmFy\n\nIf you did not ask "
                 "for this, you can ignore this email; your password will not change.\n\nThe Fabrikam team", "plain", "utf-8")
    write(FP / "ses_password_reset.eml", h, m)


def fp_mailgun():
    date = "Fri, 13 Nov 2026 09:20:01 -0800 (PST)"
    mf = "bounce+5f2e1c.9a-analyst=example.com@mg.wingtip.example"
    h = gmail(origin_host="m228-4.mailgun.net", ip="159.135.228.4", mailfrom=mf, date=date,
              ar="dkim=pass header.i=@mg.wingtip.example header.s=krs header.b=dGVzdA==;\n"
                 f"       spf=pass (google.com: domain of {mf} designates 159.135.228.4 as permitted sender) smtp.mailfrom=\"{mf}\";\n"
                 "       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=wingtip.example",
              dkim_sigs=[dkim("mg.wingtip.example", "krs", "Content-Transfer-Encoding:Content-Type:MIME-Version:Subject:Message-Id:To:From:Sender:Date")])
    h += [("Sender", "notifications@mg.wingtip.example"), ("From", "Wingtip Projects <notifications@wingtip.example>"),
          ("To", ANALYST), ("Subject", "Maria commented on Website redesign"), ("Date", "Fri, 13 Nov 2026 17:19:58 +0000"),
          ("Message-Id", "<20261113171958.6f1a2b3c4d5e6f70@mg.wingtip.example>"),
          ("In-Reply-To", "<task-5512@app.wingtip.example>"), ("References", "<task-5512@app.wingtip.example>"),
          ("X-Mailgun-Sid", "WyI1ZjJlMWMiLCAiYW5hbHlzdEBleGFtcGxlLmNvbSIsICI5YSJd"),
          ("List-Unsubscribe", "<https://app.wingtip.example/settings/notifications>")]
    m = MIMEText("Maria commented on the task \"Website redesign\":\n\n\"The new header looks great. Can we try the darker "
                 "blue for the buttons before Friday's review?\"\n\nReply in Wingtip: https://app.wingtip.example/t/5512\n\n"
                 "You get this email because you follow this task.", "plain", "utf-8")
    write(FP / "mailgun_notification.eml", h, m)


def fp_sfmc():
    date = "Fri, 13 Nov 2026 07:00:44 -0800 (PST)"
    mf = "bounce-71_HTML-1234567-88221-7001234-12@bounce.email.adventure-works.example"
    h = gmail(origin_host="mta.email.adventure-works.example", ip="13.111.4.20", mailfrom=mf, date=date,
              ar="dkim=pass header.i=@email.adventure-works.example header.s=200608 header.b=dGVzdA==;\n"
                 f"       spf=pass (google.com: domain of {mf} designates 13.111.4.20 as permitted sender) smtp.mailfrom={mf};\n"
                 "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=email.adventure-works.example",
              dkim_sigs=[dkim("email.adventure-works.example", "200608", "From:To:Subject:Date:List-Unsubscribe:MIME-Version:Reply-To:Message-ID:Content-Type")])
    h += [("From", "Adventure Works <news@email.adventure-works.example>"), ("Reply-To", "reply@email.adventure-works.example"),
          ("To", ANALYST), ("Subject", "Your winter trip planner is here"), ("Date", "Fri, 13 Nov 2026 15:00:40 +0000"),
          ("Message-ID", "<0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0@atl1s07mta2043.xt.local>"),
          ("List-Unsubscribe", "<https://click.email.adventure-works.example/subscription_center.aspx?jwt=eyJ>"),
          ("x-sfmc-stack", "7"), ("x-job", "7001234_88221")]
    m = alt("Your winter trip planner is here: routes, packing lists and hut opening times. https://www.adventure-works.example/winter",
            _newsletter_html("Adventure Works", "click.email.adventure-works.example",
                             '<p><a href="https://www.adventure-works.example/winter">Open the trip planner</a></p>'))
    write(FP / "sfmc_promo.eml", h, m)


def fp_m365_internal():
    h = [("Received", "from DM6PR11MB4610.namprd11.prod.outlook.com (2603:10b6:5:2a8::12) by\n"
                      " SA1PR11MB8278.namprd11.prod.outlook.com with HTTPS; Fri, 13 Nov 2026 10:02:11 +0000"),
         ("Received", "from DM6PR11MB4610.namprd11.prod.outlook.com\n ([fe80::5c11:7e2b:8a31:f00d]) by DM6PR11MB4610.namprd11.prod.outlook.com\n"
                      " ([fe80::5c11:7e2b:8a31:f00d%5]) with mapi id 15.20.8137.018; Fri, 13 Nov 2026\n 10:02:10 +0000"),
         ("From", "Priya Raman <priya.raman@example.com>"), ("To", "Analyst <analyst@example.com>"),
         ("Subject", "Notes from Thursday's planning meeting"), ("Thread-Topic", "Notes from Thursday's planning meeting"),
         ("Thread-Index", "AdtVb3oF2c1Y8xGqQ2+5nZ3xY0a1Bg=="), ("Date", "Fri, 13 Nov 2026 10:02:10 +0000"),
         ("Message-ID", "<DM6PR11MB46105C2B9E1A0F7D3C4B2E19A1D52@DM6PR11MB4610.namprd11.prod.outlook.com>"),
         ("Accept-Language", "en-GB, en-US"), ("Content-Language", "en-GB"),
         ("X-MS-Exchange-Organization-AuthAs", "Internal"), ("X-MS-Exchange-Organization-AuthSource", "DM6PR11MB4610.namprd11.prod.outlook.com"),
         ("X-MS-Has-Attach", ""), ("X-MS-Exchange-Organization-SCL", "-1"),
         ("X-Forefront-Antispam-Report", "SFV:SKI;SCL:-1;CIP:255.255.255.255;CTRY:;LANG:en;SCL:-1;SRV:;IPV:NLI;SFV:SKI;SFS:;DIR:INT;SFP:;PTR:;CAT:NONE;"),
         ("X-Microsoft-Antispam", "BCL:0;")]
    m = MIMEText("Hi,\n\nThanks for joining on Thursday. Notes are below; shout if I missed anything.\n\n"
                 "- Roadmap review moves to 2 December.\n- Sam owns the vendor shortlist.\n- Budget draft due next Friday.\n\n"
                 "Priya", "plain", "utf-8")
    write(FP / "m365_internal.eml", h, m)


def fp_google_calendar():
    ics = "\r\n".join([
        "BEGIN:VCALENDAR", "PRODID:-//Google Inc//Google Calendar 70.9054//EN", "VERSION:2.0", "CALSCALE:GREGORIAN",
        "METHOD:REQUEST", "BEGIN:VEVENT", "DTSTART:20261117T140000Z", "DTEND:20261117T143000Z", "DTSTAMP:20261113T120000Z",
        "ORGANIZER;CN=Sam Lee:mailto:sam.lee@example.com", "UID:3m1o2r9a0b4c@google.com",
        "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=analyst@example.com:mailto:analyst@example.com",
        "X-GOOGLE-CONFERENCE:https://meet.google.com/abc-defg-hij",
        "DESCRIPTION:Weekly sync on the vendor shortlist.\\n\\nJoin with Google Meet: https://meet.google.com/abc-defg-hij",
        "SUMMARY:Vendor shortlist sync", "STATUS:CONFIRMED", "END:VEVENT", "END:VCALENDAR", ""])
    date = "Fri, 13 Nov 2026 04:00:12 -0800 (PST)"
    h = gmail(origin_host="mail-sor-f69.google.com", ip="209.85.220.69", mailfrom="sam.lee@example.com", date=date,
              ar="dkim=pass header.i=@example.com header.s=google header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of sam.lee@example.com designates 209.85.220.69 as permitted sender) "
                 "smtp.mailfrom=sam.lee@example.com;\n       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=example.com",
              dkim_sigs=[dkim("example.com", "google", "mime-version:reply-to:sender:message-id:date:subject:from:to")])
    h += [("Reply-To", "Sam Lee <sam.lee@example.com>"), ("Sender", "Google Calendar <calendar-notification@google.com>"),
          ("From", "Sam Lee <sam.lee@example.com>"), ("To", ANALYST),
          ("Subject", "Invitation: Vendor shortlist sync @ Tue 17 Nov 2026 14:00 - 14:30 (GMT)"),
          ("Date", "Fri, 13 Nov 2026 12:00:12 +0000"), ("Message-ID", "<calendar-3m1o2r9a0b4c@google.com>")]
    cal = MIMEText(ics, "calendar", "utf-8")
    cal.set_param("method", "REQUEST")
    m = multipart([MIMEText("Sam Lee has invited you to: Vendor shortlist sync. Join with Google Meet: "
                            "https://meet.google.com/abc-defg-hij", "plain", "utf-8"), cal], "alternative")
    write(FP / "google_calendar_invite.eml", h, m)


def fp_mailing_list():
    date = "Fri, 13 Nov 2026 08:13:20 -0800 (PST)"
    h = gmail(origin_host="mail.lists.example.org", ip="140.211.11.131", mailfrom="dev-bounces@lists.example.org", date=date,
              arc="pass",
              ar="arc=pass (i=1 spf=pass spfdomain=fabrikam.example dkim=pass dkdomain=fabrikam.example dmarc=pass fromdomain=fabrikam.example);\n"
                 "       dkim=fail header.i=@fabrikam.example header.s=s2026 header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of dev-bounces@lists.example.org designates 140.211.11.131 as permitted sender) "
                 "smtp.mailfrom=dev-bounces@lists.example.org;\n"
                 "       dmarc=pass (p=REJECT sp=REJECT dis=NONE arc=pass) header.from=fabrikam.example",
              dkim_sigs=[dkim("fabrikam.example", "s2026", "from:to:subject:date:message-id:content-type")])
    h += [("From", "Dana Whitfield <dana@fabrikam.example>"), ("To", "dev@lists.example.org"),
          ("Subject", "[dev] Re: Proposal: drop Python 3.8 support"), ("Date", "Fri, 13 Nov 2026 16:12:58 +0000"),
          ("Message-ID", "<CA+dana20261113161258@mail.fabrikam.example>"),
          ("In-Reply-To", "<CA+maintainer20261112@mail.example.org>"), ("References", "<CA+maintainer20261112@mail.example.org>"),
          ("List-Id", "Developer discussion <dev.lists.example.org>"),
          ("List-Unsubscribe", "<https://lists.example.org/mailman3/postorius/lists/dev.lists.example.org/>, <mailto:dev-leave@lists.example.org>"),
          ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"), ("List-Post", "<mailto:dev@lists.example.org>"),
          ("Precedence", "list"), ("Sender", "dev-bounces@lists.example.org"), ("Reply-To", "dev@lists.example.org")]
    m = MIMEText("+1 from me. 3.8 has been end-of-life for a while and the CI matrix is getting slow.\n\nDana\n\n"
                 "_______________________________________________\ndev mailing list\nhttps://lists.example.org/mailman3/lists/dev.lists.example.org/",
                 "plain", "utf-8")
    write(FP / "mailing_list_arc.eml", h, m)


def fp_zip_attachment():
    z = zip_bytes({"Q3_report.pdf": b"%PDF-1.7\n% ESHA inert test fixture\n", "Q3_appendix.pdf": b"%PDF-1.7\n% fixture\n"})
    date = "Fri, 13 Nov 2026 03:30:04 -0800 (PST)"
    h = gmail(origin_host="mail-ed1-f44.google.com", ip="209.85.208.44", mailfrom="tom.baker@example.com", date=date,
              ar="dkim=pass header.i=@example.com header.s=google header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of tom.baker@example.com designates 209.85.208.44 as permitted sender) "
                 "smtp.mailfrom=tom.baker@example.com;\n       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=example.com",
              dkim_sigs=[dkim("example.com", "google", "mime-version:from:date:message-id:subject:to")])
    h += [("From", "Tom Baker <tom.baker@example.com>"), ("To", ANALYST), ("Subject", "Q3 report and appendix"),
          ("Date", "Fri, 13 Nov 2026 11:29:51 +0000"), ("Message-ID", "<CAOx7m1bQ3report20261113@mail.gmail.com>")]
    m = multipart([MIMEText("Hi,\n\nZipped the Q3 report and the appendix together since the attachment limit bit me "
                            "last time. Let me know if anything is missing.\n\nTom", "plain", "utf-8"),
                   attach(z, "Q3_report.zip", "application", "zip")])
    write(FP / "colleague_zip.eml", h, m)


def fp_google_groups():
    date = "Fri, 13 Nov 2026 05:05:45 -0800 (PST)"
    h = gmail(origin_host="mail-sor-f97.google.com", ip="209.85.220.97", mailfrom="volunteers+bncBC@googlegroups.com", date=date,
              ar="dkim=pass header.i=@googlegroups.com header.s=20230601 header.b=dGVzdA==;\n"
                 "       spf=pass (google.com: domain of volunteers+bncBC@googlegroups.com designates 209.85.220.97 as permitted sender) "
                 "smtp.mailfrom=volunteers+bncBC@googlegroups.com;\n"
                 "       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=googlegroups.com",
              dkim_sigs=[dkim("googlegroups.com", "20230601", "x-original-sender:list-unsubscribe:list-subscribe:list-archive:list-help:list-post:list-id:mailing-list:precedence:message-id:date:subject:to:from:mime-version:sender:from:to:cc:subject:date")])
    h += [("From", "'Leila Haddad' via Riverside Volunteers <volunteers@googlegroups.com>"),
          ("To", "Riverside Volunteers <volunteers@googlegroups.com>"), ("Reply-To", "Leila Haddad <leila@example.org>"),
          ("Subject", "Saturday clean-up: meeting point moved"), ("Date", "Fri, 13 Nov 2026 13:05:40 +0000"),
          ("Message-ID", "<b6c0a1e2-77f3-4c1d-9e0a-2f51c3d4e5f6n@googlegroups.com>"),
          ("X-Original-Sender", "leila@example.org"), ("Precedence", "list"), ("Mailing-list", "list volunteers@googlegroups.com"),
          ("List-ID", "<volunteers.googlegroups.com>"),
          ("List-Unsubscribe", "<mailto:volunteers+unsubscribe@googlegroups.com>, <https://groups.google.com/g/volunteers/subscribe>"),
          ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")]
    m = MIMEText("Hi all,\n\nThe park gate is closed for repairs, so we'll meet at the boathouse car park instead. "
                 "Same time, 9am. Gloves and bags provided.\n\nLeila", "plain", "utf-8")
    write(FP / "google_groups.eml", h, m)


def main():
    FP.mkdir(parents=True, exist_ok=True)
    for fn in (html_smuggling, archive_payloads, iso_lnk, calendar_phish, quishing, dkim_bimi_spoof, thread_hijack,
               bulk_no_unsubscribe, fp_mailchimp, fp_sendgrid_receipt, fp_ses_reset, fp_mailgun, fp_sfmc, fp_m365_internal,
               fp_google_calendar, fp_mailing_list, fp_zip_attachment, fp_google_groups):
        fn()


if __name__ == "__main__":
    main()
