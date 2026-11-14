# Email Security Header Analyzer (ESHA)

Paste an email's headers, or drop the whole `.eml` file, and ESHA tells you where the message really came from: whether SPF, DKIM and DMARC passed, which identities don't match the sender, and which signs of phishing or spoofing it shows. Analysis runs entirely on your machine and never contacts third-party services.

Built for SOC analysts, incident responders and IT admins who triage suspicious email. ESHA started from the open-source [MHA (E-Mail Header Analyzer)](https://github.com/cyberdefenders/email-header-analyzer) by [@lnxg33k](https://github.com/lnxg33k), and its analysis engine, interface, API and command line have since been rewritten.

## What it checks

**Authentication and mismatches**
- SPF, DKIM, DMARC, ARC and Microsoft composite-auth (`compauth`) verdicts, taken from the receiving server's `Authentication-Results`, or `Received-SPF` and `DKIM-Signature` when that's missing
- DMARC worked out from SPF and DKIM alignment when no verdict was recorded
- A **domain alignment table** comparing the From domain against the SPF envelope sender, each DKIM signer, Return-Path, Reply-To, Sender, Message-ID and the sending server's HELO name, using organisational domains from the Public Suffix List
- SPF or DKIM that passes for an unrelated domain while DMARC fails (the classic spoofing pattern via bulk mail services)
- Weak `p=none` DMARC policies, conflicting SPF results, and fake `Authentication-Results` headers inserted by the sender

**Sender identity**
- Look-alike domains imitating major brands: typos (`paypa1`), homoglyphs and Cyrillic/Greek confusables (`раураl`), punycode, brand names embedded in other domains
- Cousin domains of the sender's own organisation in Reply-To or links (`acmecorp-hr.com` vs `acme-corp.com`), typical of invoice and payroll fraud
- Display names that contain a different email address, or claim a brand the domain doesn't belong to
- Reply-To, Return-Path and Sender mismatches, missing Message-ID or Date, forged dates

**Route**
- Every relay hop: HELO, reverse DNS, IPv4/IPv6, protocol, TLS, timestamp and per-hop delay
- Correct handling of server clock skew and missing time zones (the original MHA reported these as 24-hour delays or crashed)
- Originating IP with country (plus city and network owner if you add the free MaxMind City/ASN databases)
- Residential or dynamic sending IPs, missing reverse DNS, bare-IP HELO greetings

**Content** (when the body is included)
- Links whose visible text points somewhere else, raw-IP links, URL shorteners, punycode and look-alike link domains, free hosting often used for phishing, open redirects, `javascript:` and `data:` links
- Risky attachments (HTML, SVG, ISO/IMG, LNK, scripts, executables, macro documents, OneNote), double extensions (`invoice.pdf.html`), and files whose content doesn't match their name
- Login and data-collection forms in the message or its attachments

**Spam filters**: Microsoft 365 (SCL, BCL, SFV, CAT such as `SPOOF` or `PHSH`) and SpamAssassin verdicts.

Every result is combined into a 0–100 risk score with a plain-language explanation for each finding. The score is heuristic: treat it as triage, not proof.

## Use it in your browser

ESHA is published as a static site on GitHub Pages: **https://0xanalyst.github.io/email-security-header-analyzer/**

The hosted version runs the same Python analyzer inside your browser tab with [Pyodide](https://pyodide.org) (WebAssembly). Headers and `.eml` files you open are never uploaded. GitHub serves the page's files and doesn't see any email content. The page's Content Security Policy (`connect-src 'self'`) blocks it from contacting any other server, and Pyodide is hosted with the site rather than loaded from a CDN. The first visit downloads about 14 MB, which your browser then caches.

To build and preview the static site yourself:
```sh
pip install -r requirements.txt
python scripts/build_site.py               # writes ./site
python -m http.server -d site 8000         # http://127.0.0.1:8000
node scripts/check_site.js site tests/samples   # optional smoke test of the in-browser engine
```
Every push to `main` rebuilds and deploys the site (`.github/workflows/pages.yml`).

## Run it locally

You need Python 3.9 or newer.

**macOS**: double-click `Start ESHA.command` in Finder, or run `./run.sh` in Terminal. If macOS says it can't verify the file, right-click it and choose **Open**. If port 8080 is busy (Burp Suite uses it by default), ESHA picks the next free port and prints it.

**Linux**
```sh
./run.sh
```

**Windows**: double-click `run.bat`.

The script creates a virtual environment, installs dependencies and opens http://127.0.0.1:8080 in your browser. Press Ctrl+C to stop.

**Manually**
```sh
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m esha --open          # options: -b 0.0.0.0 -p 9000
```

**Docker**
```sh
docker compose up -d          # http://127.0.0.1:8080
```
The image runs gunicorn as a non-root user with a read-only filesystem and a health check.

## Command line

```sh
python -m esha analyze message.eml            # colour report in the terminal
python -m esha analyze message.eml --json     # full JSON report
pbpaste | python -m esha analyze -            # headers from the clipboard (macOS)
```
`analyze` exits with code 2 when the verdict is high risk, so it can be used in scripts.

## API

```sh
curl -s localhost:8080/api/analyze -H 'Content-Type: application/json' -d '{"headers": "..."}'
curl -s localhost:8080/api/analyze -F file=@message.eml
curl -s localhost:8080/api/analyze -H 'Content-Type: message/rfc822' --data-binary @message.eml
curl -s localhost:8080/api/health
```

The response contains `score`, `findings` (each with `severity`, `title`, `detail`, `category`), `auth` (including the `alignment` table), `hops`, `origin`, `content` (links and attachments), `spam`, `summary` and the decoded `headers`.

## Keep geolocation current

The bundled GeoLite2 Country database is from 2018, so some locations are out of date. To update it, and to add city and network-owner lookups:

1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup and generate a license key.
2. Run:
   ```sh
   MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=xxxx python scripts/update_geoip.py
   ```

The databases are saved to `esha/static/data`. To keep them elsewhere, use `--dest /path` and set `ESHA_GEOIP_DIR=/path`.

## Privacy and security

- No network lookups: no DNS, no WHOIS, and no reputation APIs. Headers and messages are not stored or logged.
- Links and attachments are inspected as text only. Nothing is opened, fetched or executed.
- The web UI uses a strict Content Security Policy, no third-party scripts, fonts or CDNs, and renders all message content as text.
- By default the server listens on `127.0.0.1` only. Put it behind authentication before exposing it on a network.

## Development

```sh
pip install -r requirements-dev.txt
pytest            # 42 tests, including real-world style samples in tests/samples
ruff check esha tests
```

Project layout:

| Path | Purpose |
| --- | --- |
| `esha/core/received.py` | Received-header parsing, IP extraction, hop timing |
| `esha/core/auth.py` | Authentication-Results, ARC, DKIM-Signature, Received-SPF, spam-filter parsing |
| `esha/core/domains.py` | Organisational domains, look-alike and cousin-domain detection |
| `esha/core/body.py` | Link, attachment and form inspection |
| `esha/core/analyzer.py` | Findings, alignment and scoring |
| `esha/app.py` | Flask web app and JSON API |
| `esha/__main__.py` | Command line |
| `esha/static/js/worker.js` | In-browser engine (Pyodide) used by the static site |
| `scripts/build_site.py` | Builds the GitHub Pages site into `./site` |

## Credits and license

ESHA is derived from [MHA](https://github.com/cyberdefenders/email-header-analyzer) by @lnxg33k and contributors, and like MHA it is licensed under GPL-3.0. See [LICENSE.md](LICENSE.md). Fonts: Overpass (SIL Open Font License). IP geolocation: MaxMind GeoLite2 (CC BY-SA 4.0).
