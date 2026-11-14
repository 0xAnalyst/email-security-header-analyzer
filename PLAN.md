# ESHA roadmap

This plan covers four phases. Each one ends with `pytest`, `ruff check esha tests` and
`python -W error::SyntaxWarning -m pytest` passing on Python 3.9+. It also ends with a browser check
of the UI in light, dark and mobile widths, and a README update.

## Ground rules carried through every phase

- **Offline by default.** Network code is only added in Phase 3. It lives in its own package
  (`esha/enrich/`), is off by default, and is the only code that may open a socket.
- **Static parsing only.** Attachments are read as bytes: ZIP central directories, ISO 9660 directory
  records and text patterns. Nothing is decompressed to disk, executed or rendered.
- **JSON changes are additive.** Existing keys keep their names and meanings. New data goes in new
  keys.
- **Every detection** gets a rule ID, a unit test and a sample in `tests/samples` that triggers it. A
  regression test keeps `legit_github.eml` and the false-positive corpus out of "high".

- **Runs in the browser too.** The GitHub Pages site runs `esha.core` with Pyodide, so code under
  `esha/core/` must stay pure Python with no network access. Optional native extras, such as QR
  decoding, must degrade gracefully when they're missing, as they will be in the browser.
  `scripts/check_site.js` checks the bundled engine against the samples on every deploy.

## Conflicts between the brief and the code, and how this plan resolves them

| Brief | What the code has | Decision |
| --- | --- | --- |
| Show a stable rule ID on each finding | Findings already have an `id` field: a slug such as `spf-mismatch`, generated from the title | Keep `id` unchanged and add `rule_id` (`ESHA-xxx`), plus `attack`, `remediation`, `description` and `weight` |
| `esha/rules/*.yaml` or a Python registry | No YAML dependency | Use a Python registry (`esha/rules.py`). PyYAML would be a new dependency, and a typed registry can be checked by tests |
| Configurable weights through a config file | No config | Use a JSON config file, because `tomllib` needs Python 3.11 and the floor is 3.9. Env vars override the file |
| Decode QR codes "if a small optional dependency is available" | n/a | No small pure-Python QR decoder exists. `zxing-cpp` (a compiled wheel of about 1 MB) plus Pillow would work. **I'll ask you before adding it.** Until then ESHA flags image-only and "scan the QR code" messages without decoding them |
| Inspect password-protected or nested archives and disk images | n/a | ZIP: full listing and encryption flags (stdlib `zipfile`, central directory only). ISO/IMG: a small ISO 9660 directory parser. RAR, 7z and VHD/VHDX: no listing, because `rarfile` needs the `unrar` binary and `py7zr` is large. These are identified by magic bytes, plus a bounded scan for embedded `.lnk`/`.exe` file names |
| Several Phase 1 checks need the message body | Pasted headers have no body | Body checks (smuggling, archives, .ics, quishing, pixels) run only when a full `.eml` is supplied, as content checks do today |

## Phase 1: Detection engine and quality

**Status: done (November 2026).** 124 tests; every new rule has a sample; the 10-message false-positive corpus
scores low natively and in the browser build. What changed from the plan:
- Thread hijacking from a look-alike of a participant's domain is **critical**, not high. The attacker's
  own domain passes DMARC, so a high rating left these messages at "suspicious".
- The corpus found two false positives, now fixed: `googlegroups.com` was flagged as a Google
  look-alike, and mailing-list Reply-To, Sender and footer-broken DKIM were warnings. List allowances
  apply only when DMARC passes, so a forged `List-Id` can't exploit them.
- The receiving Microsoft 365 or Gmail server isn't treated as the sending ESP. Only the origin server,
  DKIM, envelope and Message-ID count as evidence.
- The report UI is tabbed: Findings, Route, Authentication, Links & attachments and All headers.
- Not done: QR decoding (declined), RAR and 7z full listings (would need native tools), and VHD
  partition parsing (VHDs get a bounded file-name scan instead).

### 1.1 Rule registry (`esha/rules.py`)
- A `Rule` dataclass with these fields: `id` (ESHA-NNN), `key` (the existing slug, kept for
  compatibility), `title`, `severity` (the default), `category`, `description`, `remediation`,
  `attack` (a list of ATT&CK technique IDs and names), and `weight` (optional; when unset, the severity
  weight applies).
- IDs are grouped by range so they stay stable as rules are added:
  `001–099` authentication, `100–199` sender identity, `200–299` routing, `300–399` message headers,
  `400–499` content, `500–599` spam-filter verdicts, `600–699` online enrichment (Phase 3),
  `900` input.
- `analyzer.py` emits findings with `emit(rule_key, title=None, detail=..., severity=None)`. The title and
  severity can still depend on context. For example, "SPF passed for a different domain" stays `info`
  when DMARC passes. Context can only lower a severity or pick from the rule's documented options.
- `python -m esha rules` prints the registry as a table or JSON. `docs/RULES.md` is generated from the
  registry, and a test fails if it is out of date.
- ATT&CK mapping: T1566.001 (spearphishing attachment), T1566.002 (spearphishing link),
  T1656 (impersonation), T1027.006 (HTML smuggling), T1553.005 (mark-of-the-web bypass for ISO/VHD),
  T1204.001/002 (user execution), T1036.007 (double file extension), T1585/T1583.001 (acquired
  domains, for look-alikes), T1534 (internal spearphishing, for thread hijacking).

### 1.2 Configurable scoring (`esha/config.py`)
- Defaults match today's values: severity weights 40/25/12/4/0/0, a critical floor of 80, and
  thresholds of high ≥ 60 and medium ≥ 25. **Existing scores do not change.**
- `ESHA_CONFIG=/path/esha.json`, or `./esha.json` if it exists, sets these keys:
  `{"severity_weights": {...}, "rule_weights": {"ESHA-301": 0}, "thresholds": {...}, "critical_floor": 80, "disabled_rules": [...]}`.
- `ESHA_WEIGHTS="high=30,ESHA-301=0"` overrides individual values from an env var.
- An invalid config is rejected at startup with a clear message, not ignored.
- Each finding reports the points it actually added (`weight`). `report.meta.scoring` records which
  config was used, so two analysts can tell why their scores differ.

### 1.3 New detections

| Detection | Where | Default severity | Notes |
| --- | --- | --- | --- |
| HTML smuggling in HTML/SVG attachments | `core/attachments.py` | critical (2+ indicators), high (1) | Detects `atob(`, `new Blob(`, `msSaveOrOpenBlob`, `createObjectURL`, `download=` with `data:`, and base64 runs ≥ 8 KB. Regexes are bounded, with no nested quantifiers |
| Password-protected archive | `core/attachments.py` | high | ZIP encryption flag (traditional or AES). The detail notes when the body mentions a password |
| Nested archive | same | medium | Archive inside an archive |
| Risky file inside an archive or disk image | same | critical for LNK/EXE/script, high for others | Reads file listings only |
| ISO/IMG/VHD containing LNK/EXE | same | critical | ISO 9660 parser; bounded byte scan for VHD/VHDX/UDF |
| Calendar invite phishing | `core/attachments.py` (.ics) | medium (external organiser), low/medium (links in description) | .ics links go into the normal link list, so link rules apply |
| Image-only message (possible quishing) | `core/body.py` | low | Visible text under about 25 words, images present, no or few links |
| Message asks the reader to scan a QR code | same | medium (high when DMARC fails) | |
| Tracking pixel or remote images | same | info (0 points) | Shown for context only, so newsletters are not penalised |
| Bulk mail without List-Unsubscribe | `analyzer.py` | low | Bulk means Precedence bulk/list, List-Id, a recognised ESP, BCL ≥ 4 or Feedback-ID |
| List-Unsubscribe without one-click (RFC 8058) | same | info | |
| BIMI header present | same | info; medium when DMARC fails | A sender-inserted `BIMI-Indicator` on unauthenticated mail is suspicious |
| DKIM does not sign From | `analyzer.py` | medium | |
| DKIM `l=` body-length tag | same | medium | Lets anyone append content |
| DKIM signs too few headers | same | low | For example, Subject not signed |
| Fake reply ("RE:" with no In-Reply-To/References) | same | low | |
| Thread headers with a non-reply subject | same | info | |
| Reply from a look-alike of a thread participant | same | high | Domains in References are compared with the From domain |
| ESP recognition (SendGrid, Mailchimp/Mandrill, Amazon SES, Mailgun, Salesforce MC, M365, Google Workspace, plus Postmark, SparkPost, Brevo and HubSpot) | `core/esp.py` | info | Adds `summary.esp`. Mismatch findings say "expected for <ESP>" when DMARC passes, and "anyone with a <ESP> account can do this" when it fails. Replaces the hard-coded Message-ID ESP regex |

### 1.4 False-positive corpus (`tests/samples/fp/`)
Synthesised messages using `example.*` and other placeholder domains, with no real personal data:
a Mailchimp newsletter (tracking pixels, List-Unsubscribe-Post), a SendGrid receipt, an Amazon SES
password reset, a Mailgun notification, a Salesforce Marketing Cloud promo, an internal Microsoft 365
message, a Google Calendar invite from a colleague, a Google Groups or mailman forward (broken DKIM
with an ARC pass), and a legitimate ZIP attachment of PDFs. A parametrised test asserts that none of
them scores "high" and that most score "low".

### 1.5 UI
Each finding shows its rule ID as a small tag. A finding can be expanded to show the description,
the remediation and links to the ATT&CK techniques (plain `<a>` links, no new assets). The content
section adds archive and disk-image listings and invite details. All content is still set with
`textContent`, and the CSP is unchanged.

## Phase 2: Inputs and outputs for analysts (summary)

**Status: partly done (November 2026), released as 1.1.0.**
- Done: the IOC panel and export (CSV, JSON, STIX 2.1, MISP), attachment hashes, the HTML report and
  the print layout. All are exported by one Python module (`esha/core/exports.py`) shared by the UI,
  the API (`?format=`, `/api/export`), the CLI (`-f`, `-o`) and the in-browser engine.
- `.msg` support was added in 1.2.0 with `olefile` instead of `extract-msg`. `extract-msg` would add
  about 20 packages, including `cryptography` and `cffi` (around 10 MB of compiled code), which can't run
  in the browser. `olefile` is 115 KB of pure Python and works everywhere, including GitHub Pages. The
  sample `.msg` files are made by a small compound-file writer in `scripts/make_samples.py`. They pass
  `olefile`'s strict checks, and `extract-msg` reads them correctly (checked once, outside the project).
- Still to do: `.mbox` and batch mode.
- `.msg` support through the optional `extract-msg` extra (**I'll ask first**, because it pulls in
  several packages). `.mbox` support through the stdlib `mailbox` module.
- `python -m esha batch <folder|file.mbox> --csv out.csv --json out.jsonl` and
  `POST /api/analyze/batch`, limited to 50 messages per request by default.
- IOC panel and export to CSV, JSON, STIX 2.1 and MISP event JSON. Bundles are built by hand, so no
  `stix2` dependency. Attachment SHA-256/MD5 hashes are added to the content section as new keys.
- A print stylesheet and an "Export HTML report" button. The export is one self-contained file with
  inlined CSS, no scripts and all values HTML-escaped.

## Phase 3: Opt-in online enrichment (summary)
- `--enrich` CLI flag, an `enrich: true` API field and a UI toggle that are off by default and
  labelled "Sends domains and IPs to DNS / RDAP / the services you configure".
- DNS through `dnspython` (**I'll ask**, though it is pure Python and moderate in size): SPF, DMARC,
  BIMI, MX, forward-confirmed reverse DNS and DKIM selector existence. Domain age through RDAP over
  stdlib `urllib`. AbuseIPDB, VirusTotal, URLhaus and Spamhaus DQS are queried only when their API key
  env var is set.
- Every lookup has its own timeout. A TTL cache is kept on disk in the user cache directory. Results go
  under `report.enrichment`, with `source`, `fetched_at` and `cached`, and add findings with ESHA-6xx
  IDs.

## Phase 4: Hardening and release (summary)
- `ESHA_AUTH_TOKEN` (bearer token) or basic auth. Binding to any address other than 127.0.0.1 or ::1
  without one is refused. An in-process rate limiter (token bucket per IP) protects `/api/*`.
- Hypothesis fuzz tests for the Received, Authentication-Results, DKIM-Signature, mailbox, ISO and .ics
  parsers, with time budgets to catch catastrophic regexes.
- CI adds pip-audit, a CycloneDX SBOM, a Docker base image pinned by digest, GHCR publishing and a
  PyPI wheel on `v*` tags (trusted publishing). Also adds CHANGELOG.md and SECURITY.md.

## Decisions I need from you
1. ~~Phase 1: QR decoding with `zxing-cpp`~~: declined. ESHA flags quishing without decoding the codes.
2. Phase 2: add `extract-msg` as an optional `[msg]` extra?
3. Phase 3: add `dnspython` as an optional `[enrich]` extra?
