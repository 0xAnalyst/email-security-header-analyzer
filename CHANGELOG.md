# Changelog

All notable changes to ESHA. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). The JSON report only gains fields within
a major version; existing fields are never renamed or removed.

## [1.2.0] - 2026-11-14

### Added
- **Outlook `.msg` files** in the web app, on the GitHub Pages site, through the API (file upload or an
  `application/vnd.ms-outlook` body) and on the command line. The original transport headers, plain and
  HTML bodies and attachments are rebuilt into a standard message, and embedded `.msg` attachments are
  converted recursively. Uses `olefile` (pure Python, BSD) rather than `extract-msg`, which would add
  about 20 packages, including compiled ones that can't run in the browser.
- Two informational rules: `ESHA-901` for a `.msg` without transport headers (saved from Sent Items or
  Drafts), and `ESHA-902` for a body stored only as RTF.
- Attached emails (`message/rfc822`) are listed with the attachments.
- `meta.input` records whether the input was pasted headers, an `.eml` or a `.msg`.
- An Outlook `.msg` sample on the start page.

### Changed
- The start page leads with privacy: on the hosted site, a "runs entirely in your browser" badge and
  wording that nothing is uploaded.
- For a `.msg` without transport headers, a missing route, DMARC or DKIM result is reported as a note,
  because those messages never passed through a receiving server.
- Engine files are requested with the version in the URL, so a new release never mixes with a cached
  older engine.

## [1.1.0] - 2026-11-14

### Added
- **Runs in the browser.** A GitHub Pages build runs the analyzer locally with Pyodide (WebAssembly).
  Messages are never uploaded, and a strict Content Security Policy blocks outside connections.
- **Rule registry.** Every finding has a stable rule ID (`ESHA-001` and up), a description, advice on
  what to do and MITRE ATT&CK techniques. List the rules with `python -m esha rules` or see `docs/RULES.md`.
- **Configurable scoring** through `esha.json`, `ESHA_CONFIG` or `ESHA_WEIGHTS`, validated at startup.
  Each report records the settings it used in `meta.scoring`.
- **New detections:**
  - HTML smuggling in HTML and SVG attachments.
  - Password-protected and nested archives, and risky files inside ZIP files and ISO/IMG disk images.
    RAR, VHD and UDF images get a file-name scan.
  - Calendar invites from outside organisers, and links in invites.
  - Image-only messages and QR-code phishing (detection only; ESHA doesn't decode QR codes).
  - Tracking pixels.
  - Weak DKIM signatures: From not signed, `l=` tag, or too few headers signed.
  - BIMI headers on mail that fails DMARC.
  - Fake "RE:" replies, and thread hijacking from look-alike domains.
  - Bulk mail without List-Unsubscribe or one-click unsubscribe.
- **Email service providers** (SendGrid, Mailchimp, Amazon SES, Mailgun, Salesforce Marketing Cloud and
  others) are recognised, so their expected domain mismatches are explained instead of flagged.
- **False-positive corpus** in `tests/samples/fp`: legitimate messages that must score low.
- **Tabbed report:** Findings, Route, Authentication, Links & attachments, Indicators and All headers.
- **Route timing:** every hop shows its delay and time, the slowest hop is marked in red, and hops of
  five minutes or more are highlighted.
- **Indicators (IOCs):** sender IPs, domains, URLs (raw and defanged), email addresses and attachment
  SHA-256/MD5 hashes, exportable as CSV, JSON, STIX 2.1 or a MISP event.
- **HTML report export:** a single self-contained file for tickets, plus a print layout that keeps
  every section.
- `analyze --format csv|json|stix|misp|html` and `-o FILE` on the command line, and `?format=` on
  `/api/analyze`.
- Sample buttons for the new attack types on the start page.

### Changed
- Geolocation reads GeoLite2 with `maxminddb` directly. `geoip2`, along with `aiohttp` and `requests`,
  is no longer a dependency.
- `googlegroups.com` is no longer reported as a Google look-alike.
- When DMARC passes, mailing-list Reply-To, Sender and footer-broken DKIM are reported as notes rather
  than warnings.

## [1.0.0] - 2026-11-13

### Added
- First release as ESHA: a rewritten analysis engine, phishing and authentication-mismatch detection,
  a new UI, a JSON API, a command line, tests and packaging. Based on MHA by lnxg33k.
