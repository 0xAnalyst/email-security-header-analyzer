"""High-level analysis: turn raw headers into a structured, JSON-safe report."""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from email.parser import HeaderParser

from . import auth as A
from . import esp, geo, iocs
from .body import analyze_body
from .domains import (
    FREE_MAIL,
    aligned,
    brand_in_text,
    brand_label,
    cousin_domain,
    decode_mime,
    domain_of,
    is_punycode,
    lookalike_brand,
    org_domain,
    parse_mailbox,
    parse_mailbox_list,
)
from .received import build_hops, find_ips, is_public_ip, parse_date
from .rules import BY_ID, RULES
from .scoring import DEFAULT_SEVERITY_WEIGHTS, ScoringConfig, get_config

# Kept for backwards compatibility; the active weights come from esha.core.scoring.
SEVERITY_WEIGHT = DEFAULT_SEVERITY_WEIGHTS

MAX_INPUT = 2_000_000  # characters

_KNOWN_HEADER = re.compile(
    r"^(X-[\w-]+|Received|From|To|Cc|Bcc|Subject|Date|Message-ID|Return-Path|Reply-To|Sender|"
    r"Authentication-Results|ARC-[\w-]+|DKIM-Signature|Received-SPF|Content-[\w-]+|MIME-Version|"
    r"Delivered-To|List-[\w-]+|In-Reply-To|References|Thread-[\w-]+|Accept-Language|Importance|"
    r"Precedence|Feedback-ID|Errors-To|Envelope-To)\s*:", re.IGNORECASE)
_HEADER_LINE = re.compile(r"^[!-9;-~]+:")

URGENCY = re.compile(
    r"\b(urgent|immediately|action required|verify|verification|suspend(ed)?|locked|"
    r"unusual (sign[- ]?in|activity)|password|expire[sd]?|invoice|payment|wire transfer|"
    r"gift ?card|confirm your|account (update|alert)|security alert|final notice|overdue)\b", re.IGNORECASE)

SUSPICIOUS_MAILERS = re.compile(r"(phpmailer|swiftmailer|the bat!|mass ?mail|bulk ?mail|"
                                r"atomic ?mail|sendblaster|gammadyne|php/\d)", re.IGNORECASE)

CATEGORY_RULES = [
    ("routing", re.compile(r"^(received|x-received|return-path|delivered-to|envelope-to|x-original-to|"
                           r"x-originating-ip|x-sender-ip|x-forwarded-.*)$", re.IGNORECASE)),
    ("authentication", re.compile(r"^(authentication-results|arc-.*|dkim-signature|x-google-dkim-signature|"
                                  r"received-spf|x-ms-exchange-.*auth.*|x-original-authentication-results|"
                                  r"domainkey-signature)$", re.IGNORECASE)),
    ("spam", re.compile(r"^(x-spam.*|x-forefront-antispam-report.*|x-microsoft-antispam.*|"
                        r"x-ms-exchange-organization-scl|x-mimecast-spam.*|x-proofpoint-.*|"
                        r"x-barracuda-.*|x-ironport-.*|x-rspamd.*|x-virus.*)$", re.IGNORECASE)),
    ("message", re.compile(r"^(from|to|cc|bcc|subject|date|message-id|reply-to|sender|in-reply-to|"
                           r"references|mime-version|content-.*|thread-.*|importance|priority|"
                           r"x-priority|list-.*|precedence|x-mailer|user-agent)$", re.IGNORECASE)),
]


def _category(name: str) -> str:
    for cat, rx in CATEGORY_RULES:
        if rx.match(name):
            return cat
    return "x-header" if name.lower().startswith("x-") else "other"


def normalize(text: str, from_file: bool = False) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > MAX_INPUT:
        text = text[:MAX_INPUT]
    lines = text.split("\n")
    # Drop preamble lines (e.g. "Microsoft Mail Internet Headers Version 2.0")
    while lines and not _HEADER_LINE.match(lines[0]):
        lines.pop(0)
    if from_file:
        return "\n".join(lines)
    # In pasted text, tolerate blank lines between headers.
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            j = i
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and _KNOWN_HEADER.match(lines[j]):
                i = j
                continue
            out.extend(lines[i:])
            break
        # Some UIs strip folding whitespace; re-indent obvious continuation lines.
        if out and not _HEADER_LINE.match(line) and not line[:1].isspace():
            line = " " + line
        out.append(line)
        i += 1
    return "\n".join(out)


# Set ESHA_STRICT_RULES=1 (the test suite does) to fail loudly when a finding
# uses a severity or category its rule doesn't declare.
STRICT_RULES = os.environ.get("ESHA_STRICT_RULES") == "1"


def _finding(rule_key, severity, title, detail="", category=None, id_=None):
    rule = RULES[rule_key]
    if STRICT_RULES and (severity not in rule.severities or (category and category != rule.category)):
        raise ValueError(f"{rule.id} ({rule_key}) emitted with severity={severity!r} category={category!r}")
    # "id" is the original slug (kept for compatibility); "rule_id" is the stable rule ID.
    return {"id": id_ or re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-"),
            "severity": severity, "title": title, "detail": detail, "category": rule.category,
            "rule_id": rule.id}


def _finalize(findings: list[dict], cfg: ScoringConfig) -> list[dict]:
    """Drop disabled rules and attach rule metadata and the points each finding scored."""
    out = []
    for f in findings:
        rule = BY_ID[f["rule_id"]]
        if rule.id in cfg.disabled_rules:
            continue
        f.update(weight=cfg.points(rule, f["severity"]), description=rule.description,
                 remediation=rule.remediation, attack=rule.attack_refs())
        out.append(f)
    return out


def analyze(text: str, from_file: bool = False, config: ScoringConfig | None = None, source: dict | None = None) -> dict:
    """Analyze headers or a whole message. ``source`` describes a converted input,
    such as an Outlook .msg ({"format": "msg", "transport_headers": bool, "notes": [...]})."""
    raw = normalize(text or "", from_file=from_file)
    msg = HeaderParser().parsestr(raw, headersonly=True)
    items = [(k, v) for k, v in msg.items()]
    hmap: dict[str, list[str]] = {}
    for k, v in items:
        hmap.setdefault(k.lower(), []).append(v)

    def first(name):
        vals = hmap.get(name.lower())
        return vals[0] if vals else None

    # ---------------------------------------------------------------- summary
    from_mb = parse_mailbox(first("from"))
    sender_mb = parse_mailbox(first("sender")) if first("sender") else None
    reply_to = parse_mailbox_list(first("reply-to"))
    return_path = parse_mailbox(first("return-path")) if first("return-path") else None
    date_dt, _ = parse_date(first("date") or "")
    summary = {
        "subject": decode_mime(first("subject")),
        "from": from_mb,
        "sender": sender_mb,
        "to": parse_mailbox_list(", ".join(hmap.get("to", []))),
        "cc": parse_mailbox_list(", ".join(hmap.get("cc", []))),
        "reply_to": reply_to,
        "return_path": return_path,
        "date": first("date"),
        "date_utc": date_dt.isoformat() if date_dt else None,
        "message_id": (first("message-id") or "").strip(),
        "mailer": (first("x-mailer") or first("user-agent") or "").strip(),
        "originating_ip_header": None,
    }
    for name in ("x-originating-ip", "x-sender-ip", "x-source-ip"):
        if first(name):
            ips = find_ips(first(name))
            if ips:
                summary["originating_ip_header"] = {"header": name, "ip": ips[0], "geo": geo.lookup(ips[0])}
                break

    # ------------------------------------------------------------------- hops
    hops = build_hops(hmap.get("received", []))
    for h in hops:
        h.geo = geo.lookup(h.from_ip)
    hop_dicts = [h.to_dict() for h in hops]
    timed = [h for h in hops if h.timestamp]
    total = (timed[-1].timestamp - timed[0].timestamp).total_seconds() if len(timed) > 1 else 0
    origin = None
    for h in hops:
        if h.from_ip and is_public_ip(h.from_ip):
            origin = {"hop": h.index, "ip": h.from_ip, "host": h.from_host,
                      "detail": h.from_detail, "geo": h.geo}
            break
    timing = {
        "total_seconds": max(total, 0),
        "first": timed[0].timestamp.isoformat() if timed else None,
        "last": timed[-1].timestamp.isoformat() if timed else None,
        "slowest_hop": max(hops, key=lambda h: h.delay or 0).index if any(h.delay for h in hops) else None,
    }
    # Delivery time, as Microsoft's Message Header Analyzer shows it: from the Date header
    # (when the sender's client created the message) to the last relay's timestamp.
    delivered = timed[-1].timestamp if timed else None
    summary["delivered_utc"] = delivered.astimezone(timezone.utc).isoformat() if delivered else None
    try:
        summary["delivery_seconds"] = (delivered - date_dt).total_seconds() if delivered and date_dt else None
    except TypeError:  # naive vs aware datetimes
        summary["delivery_seconds"] = None

    # ---------------------------------------------------------- authentication
    ar_list = [A.parse_authentication_results(v) for v in hmap.get("authentication-results", [])]
    arc_ar = [A.parse_arc_authentication_results(v) for v in hmap.get("arc-authentication-results", [])]
    rspf = [A.parse_received_spf(v) for v in hmap.get("received-spf", [])]
    dkim_sigs = [A.parse_dkim_signature(v) for v in hmap.get("dkim-signature", [])]
    arc_seals = [A.parse_tag_list(v) for v in hmap.get("arc-seal", [])]

    # The top-most Authentication-Results is the one added by the final
    # receiving server, and the only one that can usually be trusted.
    trusted = ar_list[0] if ar_list else None
    def results_for(method):
        return [r for r in (trusted["results"] if trusted else []) if r["method"] == method]

    from_domain = from_mb["domain"]

    # SPF
    spf = {"result": "none", "domain": "", "aligned": False, "source": None, "client_ip": None}
    s = results_for("spf")
    if s:
        r = s[0]
        spf.update(result=r["result"], source="Authentication-Results",
                   domain=domain_of(r["props"].get("smtp.mailfrom") or r["props"].get("smtp.helo") or ""))
    elif rspf:
        r = rspf[0]
        spf.update(result=r["result"], source="Received-SPF",
                   domain=domain_of(r["tags"].get("envelope-from") or r["tags"].get("helo") or ""),
                   client_ip=r["tags"].get("client-ip"))
    if not spf["domain"] and return_path:
        spf["domain"] = return_path["domain"]
    spf["aligned"] = aligned(spf["domain"], from_domain)

    # DKIM
    dk = results_for("dkim")
    dkim_results = []
    for r in dk:
        d = (r["props"].get("header.d") or domain_of(r["props"].get("header.i", "")) or "").lower()
        dkim_results.append({"result": r["result"], "domain": d, "selector": r["props"].get("header.s", ""),
                             "aligned": aligned(d, from_domain)})
    if dk:
        passing = [x for x in dkim_results if x["result"] == "pass"]
        dkim_result = "pass" if passing else dk[0]["result"]
        dkim_aligned = any(x["aligned"] for x in passing)
    elif dkim_sigs:
        dkim_result, dkim_aligned = "unverified", any(aligned(sg["domain"], from_domain) for sg in dkim_sigs)
    else:
        dkim_result, dkim_aligned = "none", False
    dkim = {"result": dkim_result, "aligned": dkim_aligned, "results": dkim_results, "signatures": dkim_sigs}

    # DMARC
    dm = results_for("dmarc")
    if dm:
        r = dm[0]
        dmarc = {"result": r["result"], "computed": False,
                 "policy": r["props"].get("policy.p") or r["props"].get("policy.dmarc"),
                 "disposition": r["props"].get("policy.dis"),
                 "header_from": r["props"].get("header.from", from_domain)}
    else:
        if (spf["result"] == "pass" and spf["aligned"]) or (dkim_result == "pass" and dkim_aligned):
            res = "pass"
        elif spf["result"] in ("none",) and dkim_result in ("none", "unverified"):
            res = "unknown"
        else:
            res = "fail"
        dmarc = {"result": res, "computed": True, "policy": None, "disposition": None, "header_from": from_domain}

    # ARC
    arc_res = results_for("arc")
    cvs = [sl.get("cv", "").lower() for sl in arc_seals]
    arc = {"result": arc_res[0]["result"] if arc_res else ("present" if arc_seals else "none"),
           "sets": len(arc_seals), "chain_validation": cvs,
           "results": arc_ar}

    compauth = results_for("compauth")
    authn = {
        "spf": spf, "dkim": dkim, "dmarc": dmarc, "arc": arc,
        "compauth": {"result": compauth[0]["result"], "reason": compauth[0]["reason"]} if compauth else None,
        "authserv_id": trusted["authserv_id"] if trusted else None,
        "authentication_results": ar_list,
        "received_spf": rspf,
    }
    spam = {"microsoft": A.parse_ms_antispam(hmap), "spamassassin": A.parse_spam_status(hmap)}

    # Email service provider, so expected envelope / DKIM / Message-ID mismatches can be explained.
    esp_info = esp.detect(
        hmap, envelope=spf["domain"] or (return_path or {}).get("domain", ""),
        dkim_domains=[x["domain"] for x in dkim_results] or [sg["domain"] for sg in dkim_sigs],
        message_id_domain=domain_of(summary["message_id"].strip("<>")),
        relay_hosts=[(origin or {}).get("host", "").lower(),
                     (origin or {}).get("detail", "").split("[")[0].strip().rstrip(".").lower()])
    summary["esp"] = esp_info

    # Mailing lists legitimately set Reply-To/Sender to the list and break DKIM with footers.
    list_id = " ".join(hmap.get("list-id", []))
    m_list = re.search(r"<([^<>\s]+)>", list_id)
    list_domain = (m_list.group(1) if m_list else "").lower()
    is_list = bool(list_domain) or " ".join(hmap.get("precedence", [])).strip().lower() == "list"
    original_sender = domain_of(first("x-original-sender") or "")

    def list_identity(domain: str) -> bool:
        """True if ``domain`` is the mailing list itself or the list's original poster.

        Only when DMARC passes: List-Id is sender-controlled, so a spoofer could add one."""
        return bool(is_list and dmarc["result"] == "pass" and domain and ((list_domain and aligned(domain, list_domain)) or
                                            (original_sender and aligned(domain, original_sender))))

    def esp_note(domain: str) -> str:
        """Explain a mismatching domain that belongs to the detected ESP."""
        owner = esp.esp_of_domain(domain)
        if not owner:
            return ""
        if dmarc["result"] == "pass":
            return f" {domain} belongs to {owner}; this is expected when an organisation sends through {owner}."
        return (f" {domain} belongs to {owner}, and anyone with a {owner} account gets this pass. "
                f"It says nothing about whether {from_domain} sent the message.")

    # ----------------------------------------------------------- indicators
    F: list[dict] = []
    # A .msg saved from Sent Items or Drafts never passed a receiving server, so a
    # missing route or authentication result is expected rather than suspicious.
    no_transport = bool(source and source.get("format") == "msg" and not source.get("transport_headers"))
    if not items:
        F.append(_finding("no-headers", "info", "No headers found", "The input did not contain any recognisable email headers.", "input"))
    if not hops and items:
        F.append(_finding("no-received", "info" if no_transport else "medium", "No Received headers",
                          "There is no relay path. These may not be the original headers, or the message was injected locally.",
                          "routing"))

    # authentication findings
    if dmarc["result"] == "pass":
        F.append(_finding("dmarc-pass", "pass", "DMARC passed" + (" (computed)" if dmarc["computed"] else ""),
                          f"The visible From domain ({from_domain or 'n/a'}) is authenticated.", "authentication"))
    elif dmarc["result"] in ("fail", "permerror", "temperror"):
        pol = f" Domain policy: p={dmarc['policy']}." if dmarc.get("policy") else ""
        if (dmarc.get("policy") or "").lower() == "none":
            pol += " With p=none the domain owner asks receivers not to block spoofed mail, so it may still reach inboxes."
        F.append(_finding("dmarc-fail", "high", "DMARC failed" + (" (computed)" if dmarc["computed"] else ""),
                          f"The From domain ({from_domain}) could not be authenticated by aligned SPF or DKIM.{pol}",
                          "authentication"))
    if dmarc["result"] == "pass" and (dmarc.get("policy") or "").lower() == "none":
        F.append(_finding("dmarc-policy-none", "info", "Sender's DMARC policy is p=none",
                          f"{from_domain} only monitors spoofing; it does not ask receivers to block it.", "authentication"))
    if dmarc["result"] in ("none", "unknown", "bestguesspass") and items and from_domain:
        F.append(_finding("dmarc-missing", "info" if no_transport else "low", "No DMARC verdict",
                          f"No DMARC result was recorded for {from_domain}; the sender may not publish a DMARC policy.",
                          "authentication"))

    dmarc_ok = dmarc["result"] == "pass"
    if spf["result"] == "pass" and spf["aligned"]:
        F.append(_finding("spf-aligned", "pass", "SPF passed and aligned", f"Envelope domain {spf['domain'] or 'n/a'} matches From.", "authentication"))
    elif spf["result"] == "pass":
        F.append(_finding("spf-mismatch", "info" if dmarc_ok else "medium", "SPF passed for a different domain",
                          f"The server is authorised to send for {spf['domain'] or 'the envelope domain'}, not for the From domain {from_domain}."
                          + (esp_note(spf["domain"]) or ("" if dmarc_ok else
                             " An SPF pass on an unrelated domain is a common way to make spoofed mail look authenticated.")),
                          "authentication", "spf-mismatch"))
    elif spf["result"] in ("fail", "hardfail"):
        F.append(_finding("spf-fail", "high", "SPF failed", f"The sending server is not authorised to send for {spf['domain'] or 'the envelope domain'}.", "authentication"))
    elif spf["result"] == "softfail":
        F.append(_finding("spf-softfail", "medium", "SPF soft-failed", f"The sending server is probably not authorised for {spf['domain'] or 'the envelope domain'}.", "authentication"))
    elif spf["result"] in ("permerror", "temperror"):
        F.append(_finding("spf-error", "low", f"SPF {spf['result']}", "The SPF record could not be evaluated.", "authentication"))

    if dkim_result == "pass" and dkim_aligned:
        F.append(_finding("dkim-aligned", "pass", "DKIM signature valid and aligned",
                          ", ".join(f"d={x['domain']}" for x in dkim_results if x["result"] == "pass"), "authentication"))
    elif dkim_result == "pass":
        signers = ", ".join(sorted({x["domain"] for x in dkim_results if x["result"] == "pass"}))
        F.append(_finding("dkim-mismatch", "info" if dmarc_ok else "medium", "DKIM signed by a different domain",
                          f"Valid signature from {signers}, but none from {from_domain}."
                          + ("".join(esp_note(d) for d in sorted({x["domain"] for x in dkim_results if x["result"] == "pass"}))
                             or ("" if dmarc_ok else " The signature proves who sent it, and it isn't the domain shown in From.")),
                          "authentication", "dkim-mismatch"))
    elif dkim_result in ("fail", "permerror", "temperror", "neutral", "policy"):
        list_broke_it = is_list and arc["result"] == "pass"
        F.append(_finding("dkim-fail", "info" if list_broke_it else "medium", f"DKIM {dkim_result}",
                          "The author's signature was broken by the mailing list (it adds a footer or subject tag); "
                          "the ARC seal shows authentication passed before the list changed it." if list_broke_it else
                          "A DKIM signature was present but did not verify — the message may have been altered.", "authentication"))
    elif dkim_result == "none" and items:
        F.append(_finding("dkim-none", "info" if no_transport else "low", "Message is not DKIM-signed", "", "authentication"))
    if dkim_result == "unverified":
        F.append(_finding("dkim-unverified", "info", "DKIM signature present but no verification result",
                          "No Authentication-Results header from the receiving server was included.", "authentication"))

    if compauth and compauth[0]["result"] in ("fail", "softfail"):
        F.append(_finding("compauth-fail", "high" if compauth[0]["result"] == "fail" else "medium",
                          f"Microsoft composite authentication {compauth[0]['result']}",
                          f"reason={compauth[0]['reason']}", "authentication"))
    if any(cv == "fail" for cv in cvs) or arc["result"] == "fail":
        F.append(_finding("arc-broken", "medium", "ARC chain is broken", "A forwarding service's authentication seal failed validation.", "authentication"))

    # conflicting / forged authentication results
    if s and rspf and rspf[0]["result"] and s[0]["result"] != rspf[0]["result"]:
        F.append(_finding("spf-conflict", "low", "Conflicting SPF results",
                          f"Authentication-Results says {s[0]['result']} but Received-SPF says {rspf[0]['result']}.", "authentication"))
    relay_orgs = {org_domain(h.by_host) for h in hops if h.by_host and "." in h.by_host}
    for extra in ar_list[1:]:
        sid = (extra["authserv_id"] or "").lower()
        claims_pass = any(r["result"] == "pass" for r in extra["results"] if r["method"] in ("dmarc", "spf", "dkim"))
        if sid and claims_pass and org_domain(sid) not in relay_orgs and dmarc["result"] != "pass":
            F.append(_finding("forged-ar", "medium", "Authentication-Results from an unexpected server",
                              f"A lower Authentication-Results header from {sid} claims a pass, but {sid} does not appear in the relay path. "
                              "Senders sometimes insert fake results to fool analysts.", "authentication", "forged-ar"))
            break

    # origin server reputation signals (offline)
    origin_hop = next((h for h in hops if origin and h.index == origin["hop"]), None)
    if origin_hop:
        detail = origin_hop.from_detail.lower()
        rdns = detail.split("[")[0].strip().rstrip(".") if "[" in detail else ""
        if rdns == "unknown":
            F.append(_finding("no-rdns", "low", "Sending server has no reverse DNS",
                              f"{origin_hop.from_ip} did not resolve to a hostname at the receiving server.", "routing", "no-rdns"))
        host_for_check = rdns if rdns not in ("", "unknown") else origin_hop.from_host.lower()
        if re.search(r"(\d{1,3}[-.]){3}\d{1,3}|\b(dsl|adsl|dyn|dynamic|dhcp|pool|cable|ppp|pppoe|dial|cust|broadband|residential|"
                     r"res\.|user|client|ip-\d)", host_for_check):
            F.append(_finding("dynamic-ip", "medium", "Sent from a residential or dynamic IP",
                              f"{host_for_check} looks like a home or dynamic connection, not a mail server.", "routing", "dynamic-ip"))
        helo = origin_hop.from_host.lower().strip("[]")
        if helo and _looks_ip(helo):
            F.append(_finding("helo-bare-ip", "low", "Sending server greeted with a bare IP address",
                              f"HELO {helo}; real mail servers normally use their hostname.", "routing"))

    # sender identity findings
    if from_mb["address"]:
        name = from_mb["name"]
        emb = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", name or "")
        if emb and domain_of(emb.group(0)) and not aligned(domain_of(emb.group(0)), from_domain):
            F.append(_finding("display-name-email", "high", "Display name contains a different email address",
                              f'Shows "{emb.group(0)}" but the real sender is {from_mb["address"]}.', "identity"))
        la = lookalike_brand(from_domain)
        if la:
            kind = {"homoglyph": "uses look-alike characters", "typo": "is one character off",
                    "embedded": "embeds the brand name"}[la["reason"]]
            F.append(_finding("lookalike-sender", "critical" if la["reason"] != "embedded" else "high",
                              f"Look-alike domain imitating {brand_label(la['brand'])}",
                              f"{from_domain} {kind}; the genuine domain is {la['legit_domain']}.", "identity"))
        brand = brand_in_text(name)
        if brand and not la:
            from .domains import BRANDS, LEGIT_EXTRA
            legit = BRANDS[brand]
            if org_domain(from_domain) != org_domain(legit) and org_domain(from_domain) not in LEGIT_EXTRA \
                    and not org_domain(from_domain).startswith(brand + "."):
                F.append(_finding("display-name-brand", "medium" if dmarc["result"] == "pass" else "high",
                                  f"Display name claims to be {brand_label(brand)}",
                                  f'Name "{name}" but sent from {from_domain}, not {legit}.', "identity"))
        if is_punycode(from_domain):
            F.append(_finding("sender-punycode", "medium", "Sender domain uses punycode (IDN)",
                              _idna(from_domain), "identity"))
        if org_domain(from_domain) in FREE_MAIL:
            F.append(_finding("free-mail", "info", "Sent from a free webmail provider", from_domain, "identity"))
    elif items:
        F.append(_finding("from-missing", "medium", "From header missing or unparseable", "", "identity"))

    for rt in reply_to:
        if rt["domain"] and from_domain and cousin_domain(rt["domain"], from_domain):
            F.append(_finding("reply-to-cousin", "critical", "Reply-To imitates the sender's domain",
                              f"Replies go to {rt['domain']}, a look-alike of {from_domain}. This is typical of invoice and payroll fraud.",
                              "identity", "reply-to-cousin"))
            break
        if rt["domain"] and from_domain and not aligned(rt["domain"], from_domain):
            via_list = list_identity(rt["domain"])
            F.append(_finding("reply-to-mismatch", "info" if via_list else "medium", "Reply-To differs from From",
                              f"Replies go to {rt['address']} instead of {from_domain}"
                              + (" (normal for a mailing list)." if via_list else "."), "identity"))
            break
    if return_path and return_path["domain"] and from_domain and not aligned(return_path["domain"], from_domain):
        F.append(_finding("return-path-mismatch", "info", "Return-Path differs from From",
                          f"Bounces go to {return_path['domain']}"
                          + (f" ({esp.esp_of_domain(return_path['domain'])} bounce handling)." if esp.esp_of_domain(return_path["domain"])
                             else " (common for mailing services)."), "identity"))
    if sender_mb and sender_mb["domain"] and from_domain and not aligned(sender_mb["domain"], from_domain):
        F.append(_finding("sender-mismatch", "info" if list_identity(sender_mb["domain"]) else "low",
                          "Sender header differs from From", f"Sender: {sender_mb['address']}", "identity"))

    mid = summary["message_id"]
    if not mid and items:
        F.append(_finding("message-id-missing", "medium", "Message-ID missing", "Legitimate mail servers almost always add one.", "message"))
    elif mid and from_domain:
        mdom = domain_of(mid.strip("<>"))
        if mdom and not aligned(mdom, from_domain) and not re.search(
                r"(google|outlook|prod\.outlook|amazonses|sendgrid|mailgun|mandrillapp|sparkpost|"
                r"mailchimp|mcsv|salesforce|exacttarget|mail\.gmail)", mdom) and not esp.esp_of_domain(mdom):
            F.append(_finding("message-id-mismatch", "info", "Message-ID domain differs from From", mdom, "message"))

    if summary["mailer"] and SUSPICIOUS_MAILERS.search(summary["mailer"]):
        F.append(_finding("bulk-mailer", "low", "Bulk or scripted mailer", summary["mailer"], "message"))
    if summary["subject"] and URGENCY.search(summary["subject"]):
        F.append(_finding("urgent-subject", "low", "Urgent or account-related wording in subject",
                          f'Matched "{URGENCY.search(summary["subject"]).group(0)}"', "message"))
    if not first("date") and items:
        F.append(_finding("date-missing", "medium", "Date header missing", "", "message"))
    elif not date_dt:
        F.append(_finding("date-unparseable", "low", "Date header could not be parsed", first("date"), "message"))
    elif timed:
        delta = (date_dt - timed[0].timestamp).total_seconds()
        if delta > 900:
            F.append(_finding("date-after-relay", "low", "Date header is later than the first relay",
                              f"By {int(delta // 60)} minutes — the Date may have been forged.", "message"))
        elif delta < -7 * 86400:
            F.append(_finding("date-old", "low", "Message was written long before it was sent",
                              f"{int(-delta // 86400)} days between Date and first relay.", "message"))
    if items and not summary["to"] and not hmap.get("to"):
        F.append(_finding("no-recipients", "low", "No To recipients", "Recipients were hidden (Bcc / undisclosed).", "message"))
    F.extend(_header_checks(hmap, summary, dmarc, dkim_sigs, spam, esp_info, from_domain, bool(items)))
    if source and source.get("format") == "msg":
        if not source.get("transport_headers"):
            F.append(_finding("msg-no-transport", "info", "Outlook .msg without transport headers", source["notes"][0]
                              if source.get("notes") else ""))
        if any("compressed RTF" in n for n in source.get("notes", [])):
            F.append(_finding("msg-rtf-body", "info", "Message body not readable",
                              "Only compressed RTF is stored; links and forms in the body were not checked."))

    # routing findings
    skewed = [h for h in hops if h.clock_skew]
    if skewed:
        F.append(_finding("clock-skew", "info", "Clock skew between relays",
                          "Hop " + ", ".join(f"{h.index} ({h.clock_skew:+.0f}s)" for h in skewed)
                          + " is timestamped before the previous hop — usually a mis-set server clock.", "routing"))
    slow = [h for h in hops if (h.delay or 0) >= 3600]
    if slow:
        F.append(_finding("delivery-delay", "info", "Significant delivery delay",
                          ", ".join(f"hop {h.index}: {_human(h.delay)}" for h in slow), "routing"))
    notz = [h for h in hops if h.timestamp and not h.timestamp_has_tz]
    if notz:
        F.append(_finding("no-timezone", "info", "Timestamps without a time zone",
                          "Assumed UTC for hop " + ", ".join(str(h.index) for h in notz) + ".", "routing"))
    ext = [h for h in hops if h.from_ip and is_public_ip(h.from_ip)]
    if ext and all(h.tls for h in ext):
        F.append(_finding("tls-all", "pass", "Encrypted in transit", "Every relay from a public IP used TLS.", "routing"))
    elif ext and any(not h.tls for h in ext):
        plain = [str(h.index) for h in ext if not h.tls]
        F.append(_finding("tls-partial", "info", "Some relays show no sign of TLS", "Hop " + ", ".join(plain), "routing"))

    ms = spam["microsoft"]
    try:
        scl = int(ms.get("SCL", "-1"))
    except ValueError:
        scl = -1
    if scl >= 5:
        F.append(_finding("ms-spam", "medium", f"Microsoft 365 marked as spam (SCL {scl})", f"SFV={ms.get('SFV', '')} CAT={ms.get('CAT', '')}", "spam"))
    if ms.get("CAT") in ("PHSH", "HPHSH", "HPHISH", "MALW", "SPOOF", "GIMP", "UIMP", "DIMP"):
        F.append(_finding("ms-category", "high", f"Microsoft 365 category: {ms['CAT']}", "Microsoft's filter classified this message as phishing, spoofing, impersonation or malware.", "spam"))
    try:
        bcl = int(ms.get("BCL", "-1"))
    except ValueError:
        bcl = -1
    if bcl >= 7:
        F.append(_finding("bulk-bcl", "low", f"Bulk mail (BCL {bcl})", "", "spam"))
    sa = spam["spamassassin"]
    if sa.get("flagged"):
        F.append(_finding("spamassassin", "medium", "Flagged as spam by SpamAssassin",
                          f"score {sa.get('score')}/{sa.get('required')}", "spam"))

    # ---------------------------------------------------------------- content
    body = None
    try:
        body = analyze_body(raw, from_domain)
    except Exception:
        body = None
    if body:
        for a in body["attachments"]:
            if a["content_mismatch"] == "Windows executable" or a["double_extension"]:
                F.append(_finding("disguised-attachment", "critical", "Disguised attachment",
                                  f"{a['filename']}" + (" is really a Windows program" if a["content_mismatch"] == "Windows executable"
                                                        else " uses a double extension to hide its real type"), "content"))
            elif a["risky"]:
                F.append(_finding("risky-attachment", "high", f"Risky attachment: {a['kind']}", a["filename"], "content"))
            elif a["kind"] == "archive":
                F.append(_finding("archive-attachment", "low", "Archive attachment", f"{a['filename']} can hide its contents from scanners.", "content"))
        F.extend(_content_checks(body, summary, dmarc, from_domain))
        if body["password_field"] or any(f["action"] for f in body["forms"]):
            F.append(_finding("credential-form", "high", "Message contains a login or data form",
                              "Legitimate services do not ask you to enter credentials inside an email or attachment.", "content"))
        groups = [
            ("look-alike of", "link-lookalike", "critical", "Link to a look-alike domain"),
            ("text shows", "link-text-mismatch", "high", "Link text does not match where it goes"),
            ("script link", "script-link", "high", "Script link in message"),
            ("data: URI", "data-uri-link", "high", "Link opens an embedded page"),
            ("file / network-share", "file-share-link", "high", "Link to a file share"),
            ("raw IP address", "raw-ip-link", "medium", "Link points to a raw IP address"),
            ("punycode", "punycode-link", "medium", "Link uses a punycode domain"),
            ("credentials-style @", "at-in-url", "medium", "Link hides its real host after an @"),
            ("free hosting", "free-hosting-link", "medium", "Link to free hosting often used for phishing"),
            ("URL shortener", "shortener-link", "low", "Shortened link hides its destination"),
        ]
        for key, rule_key, sev, title in groups:
            hits = [lk for lk in body["links"] if any(f.startswith(key) or key in f for f in lk["flags"])]
            if hits:
                eg = "; ".join(next(f for f in lk["flags"] if key in f) if key in ("text shows", "look-alike of") else (lk["host"] or lk["href"][:60])
                               for lk in hits[:3])
                F.append(_finding(rule_key, sev, title + (f" ({len(hits)})" if len(hits) > 1 else ""), eg, "content",
                                  re.sub(r"[^a-z]+", "-", key).strip("-")))
        cousins = sorted({lk["host"] for lk in body["links"] if lk["host"] and cousin_domain(lk["host"], from_domain)})
        if cousins:
            F.append(_finding("link-cousin", "high", "Link to a look-alike of the sender's domain", ", ".join(cousins[:3]), "content", "link-cousin"))
        if body["link_count"] and from_domain and not any(lk["same_org_as_sender"] for lk in body["links"] if lk["host"]):
            F.append(_finding("no-sender-links", "info", "No links point to the sender's own domain",
                              f"{len(body['domains'])} linked domain(s), none belong to {from_domain}.", "content"))

    # domain alignment table: everything that claims an identity, compared to From
    alignment = [{"label": "From (what you see)", "domain": from_domain, "aligned": None, "note": "reference"}]
    def _al(label, dom, note=""):
        if dom:
            alignment.append({"label": label, "domain": dom, "aligned": aligned(dom, from_domain) if from_domain else None,
                              "lookalike": bool(from_domain and cousin_domain(dom, from_domain)), "note": note})
    _al("SPF envelope sender", spf["domain"], f"SPF {spf['result']}")
    for x in dkim_results:
        _al("DKIM signer (d=)", x["domain"], f"DKIM {x['result']}")
    if not dkim_results:
        for sg in dkim_sigs:
            _al("DKIM signer (d=)", sg["domain"], "not verified")
    if return_path:
        _al("Return-Path", return_path["domain"], "where bounces go")
    for rt in reply_to:
        _al("Reply-To", rt["domain"], "where replies go")
    if sender_mb:
        _al("Sender", sender_mb["domain"])
    _al("Message-ID", domain_of(summary["message_id"].strip("<>")), "generated by the sending system")
    if origin_hop:
        helo = origin_hop.from_host.strip("[]")
        if helo and not _looks_ip(helo) and "." in helo:
            _al("Sending server (HELO)", helo.lower(), origin_hop.from_ip or "")
    authn["alignment"] = alignment

    # ----------------------------------------------------------------- score
    cfg = config or get_config()
    order = ["critical", "high", "medium", "low", "info", "pass"]
    F = _finalize(F, cfg)
    F.sort(key=lambda f: order.index(f["severity"]))
    score = min(100, sum(f["weight"] for f in F))
    if cfg.critical_floor is not None and any(f["severity"] == "critical" for f in F):
        score = max(score, cfg.critical_floor)
    level, label = cfg.level(score)
    if not items:
        level, label = "none", "No data"

    headers = [{"name": k, "value": decode_mime(v) if k.lower() in ("subject", "from", "to", "cc", "reply-to", "sender") else v,
                "category": _category(k)} for k, v in items]

    report = {
        "summary": summary,
        "hops": hop_dicts,
        "timing": timing,
        "origin": origin,
        "auth": authn,
        "spam": spam,
        "content": body,
        "findings": F,
        "score": {"value": score, "level": level, "label": label},
        "headers": headers,
        "stats": {"header_count": len(items), "hop_count": len(hops),
                  "findings": {s: sum(1 for f in F if f["severity"] == s) for s in order}},
        "meta": {"analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "geoip": geo.database_info(), "scoring": cfg.describe(),
                 "input": source or {"format": "eml" if from_file else "headers"}},
    }
    report["iocs"] = iocs.extract(report)
    return report


REPLY_PREFIX = re.compile(r"^\s*(?:\[[^\]]{1,40}\]\s*)?(?:re|aw|sv|vs|antw|odp|rif|res|ynt)\s*(?:\[\d+\]|\(\d+\))?\s*[:\uff1a]",
                          re.IGNORECASE)
FWD_PREFIX = re.compile(r"^\s*(?:\[[^\]]{1,40}\]\s*)?(?:fwd?|fw|wg|tr|enc)\s*[:\uff1a]", re.IGNORECASE)
_MSGID = re.compile(r"<([^<>@\s]{1,200}@[^<>\s]{1,200})>")


def _header_checks(hmap, summary, dmarc, dkim_sigs, spam, esp_info, from_domain, has_headers) -> list[dict]:
    """Header-only detections added in ESHA 1.1: ESP, DKIM signature quality, BIMI, threads, bulk mail."""
    F: list[dict] = []
    if esp_info:
        F.append(_finding("esp-detected", "info", f"Sent through {esp_info['name']}",
                          "Evidence: " + "; ".join(esp_info["evidence"][:4]) + "."))

    # DKIM signature quality. Only signatures with a readable h= list are judged.
    unsigned_from, partial_body, few = [], [], []
    for sg in dkim_sigs:
        hs = sg["signed_headers"]
        d = sg["domain"] or "unknown domain"
        if hs and "from" not in hs:
            unsigned_from.append(f"d={d} signs {', '.join(dict.fromkeys(hs[:8]))} but not From")
        elif hs and ("subject" not in hs or len(set(hs)) < 4):
            few.append(f"d={d} signs only {', '.join(sorted(set(hs)))}")
        if (sg.get("body_length") or "").strip():
            partial_body.append(f"d={d} has l={sg['body_length'].strip()}: anything after the first "
                                f"{sg['body_length'].strip()} bytes of the body is not covered")
    if unsigned_from:
        F.append(_finding("dkim-from-unsigned", "medium", "DKIM signature does not cover From", "; ".join(unsigned_from) + "."))
    if partial_body:
        F.append(_finding("dkim-body-length", "medium", "DKIM signature only covers part of the body (l= tag)",
                          "; ".join(partial_body) + "."))
    if few:
        F.append(_finding("dkim-few-headers", "low", "DKIM signature covers few headers", "; ".join(few) + "."))

    # BIMI: receivers add BIMI-Location / BIMI-Indicator only after DMARC passes.
    bimi = [n for n in ("bimi-indicator", "bimi-location") if hmap.get(n)]
    if bimi:
        loc = re.search(r"\bl=\s*(https://[^\s;]+)", " ".join(hmap.get("bimi-location", [])))
        if dmarc["result"] == "pass":
            F.append(_finding("bimi-present", "info", "BIMI brand logo",
                              f"{from_domain} has a verified BIMI logo" + (f" ({loc.group(1)})." if loc else ".")))
        else:
            F.append(_finding("bimi-unauthenticated", "medium", "BIMI header on unauthenticated mail",
                              f"{' and '.join(h.upper() for h in bimi)} present while DMARC is {dmarc['result']}. "
                              "The sender probably added it to borrow a brand logo."))

    # Threads: fake replies and look-alike thread participants.
    subject = summary["subject"] or ""
    thread_hdrs = " ".join(hmap.get("in-reply-to", []) + hmap.get("references", []))
    in_thread = bool(thread_hdrs.strip())
    if has_headers and REPLY_PREFIX.match(subject) and not in_thread:
        F.append(_finding("fake-reply", "low", "Subject looks like a reply, but the message isn't part of a thread",
                          f'"{subject[:80]}" has a reply prefix but no In-Reply-To or References headers.'))
    elif in_thread and subject and not REPLY_PREFIX.match(subject) and not FWD_PREFIX.match(subject):
        F.append(_finding("thread-subject-mismatch", "info", "Thread headers with a new subject",
                          f'"{subject[:80]}" is not a reply or forward, but the message references an earlier one.'))
    if in_thread and from_domain:
        participants = {domain_of(m) for m in _MSGID.findall(thread_hdrs)[:50]}
        participants |= {m["domain"] for m in summary["to"] + summary["cc"]}
        look = sorted({d for d in participants if d and cousin_domain(from_domain, d)})
        if look:
            F.append(_finding("thread-hijack-lookalike", "critical", "Reply from a look-alike of a thread participant's domain",
                              f"{from_domain} imitates {', '.join(look[:3])}, which appears in the conversation."))

    # Bulk mail and unsubscribe headers (Gmail/Yahoo bulk-sender rules, RFC 8058).
    precedence = " ".join(hmap.get("precedence", [])).strip().lower()
    try:
        bcl = int(spam["microsoft"].get("BCL", "-1"))
    except ValueError:
        bcl = -1
    bulk_why = ([f"Precedence: {precedence}"] if precedence in ("bulk", "list", "junk") else []) \
        + (["List-Id header"] if hmap.get("list-id") else []) + ([f"Microsoft BCL {bcl}"] if bcl >= 4 else [])
    unsub = " ".join(hmap.get("list-unsubscribe", []))
    if bulk_why and not unsub.strip():
        F.append(_finding("bulk-no-unsubscribe", "low", "Bulk mail without List-Unsubscribe",
                          f"Marked as bulk ({', '.join(bulk_why)}) but there is no way to unsubscribe."))
    if re.search(r"<\s*https?://", unsub, re.IGNORECASE) and not hmap.get("list-unsubscribe-post"):
        F.append(_finding("unsubscribe-no-one-click", "info", "List-Unsubscribe without one-click",
                          "No List-Unsubscribe-Post: List-Unsubscribe=One-Click header (RFC 8058)."))
    return F


def _content_checks(body, summary, dmarc, from_domain) -> list[dict]:
    """Body detections added in ESHA 1.1: HTML smuggling, archives and disk images,
    calendar invites, image-only / QR-code messages and tracking pixels."""
    F: list[dict] = []
    for a in body["attachments"]:
        if a.get("smuggling"):
            F.append(_finding("html-smuggling", "critical" if len(a["smuggling"]) >= 2 else "high",
                              "HTML smuggling in attachment", f"{a['filename']}: {', '.join(a['smuggling'])}."))
        c = a.get("container")
        if not c:
            continue
        approx = "" if c["listing"] == "complete" else f" (from {c['listing']}; the listing may be incomplete)"
        if c["encrypted"]:
            F.append(_finding("encrypted-archive", "high", "Password-protected archive",
                              f"{a['filename']} ({c['format']}) is encrypted, so its contents can't be scanned."
                              + (" The message text appears to give the password." if body.get("password_in_text") else "")))
        if c["nested"]:
            F.append(_finding("nested-archive", "medium", "Archive inside an archive",
                              f"{a['filename']} contains {', '.join(c['nested'][:3])}{approx}."))
        if c["risky"]:
            severe = any(r["severe"] for r in c["risky"])
            F.append(_finding("risky-file-in-container", "critical" if severe else "high",
                              "Risky file inside archive or disk image",
                              f"{a['filename']} ({c['format']}) contains "
                              + ", ".join(r["name"] for r in c["risky"][:4])
                              + (f" and {len(c['risky']) - 4} more" if len(c["risky"]) > 4 else "") + approx + "."))

    for cal in body.get("calendar", []):
        org = domain_of(cal["organizer"])
        external = bool(org and from_domain and not aligned(org, from_domain))
        if external:
            F.append(_finding("ics-external-organiser", "medium", "Calendar invite from an outside organiser",
                              f"Organiser {cal['organizer']} is not part of the sender's domain {from_domain}"
                              + (f' ("{cal["summary"]}")' if cal["summary"] else "") + "."))
        if cal["links"]:
            trusted = not external and dmarc["result"] == "pass"
            F.append(_finding("ics-links", "info" if trusted else "low", "Links in a calendar invite",
                              ", ".join(_host_of(u) or u[:60] for u in cal["links"][:3])
                              + (f" and {len(cal['links']) - 3} more" if len(cal["links"]) > 3 else "") + "."))
        if external or cal["links"]:
            break  # one invite is enough to report

    imgs = body.get("images") or {}
    has_images = bool(imgs.get("html_images") or imgs.get("inline_parts") or imgs.get("attached"))
    qr = body.get("qr_wording") or ""
    subject_qr = QR_SUBJECT.search(summary["subject"] or "")
    if has_images and (qr or subject_qr):
        F.append(_finding("qr-lure", "medium" if dmarc["result"] == "pass" else "high", "Message asks you to scan a QR code",
                          f'The message says "{(qr or subject_qr.group(0))[:60]}" and contains an image.'
                          + ("" if dmarc["result"] == "pass" else " The sender is not authenticated.")))
    if has_images and body.get("text_words", 0) < 25 and body["link_count"] <= 2:
        F.append(_finding("image-only", "low", "Message is mostly an image",
                          f"{body.get('text_words', 0)} words of text and {body['link_count']} link(s); "
                          "the content is in images that filters can't read."))
    if imgs.get("remote"):
        F.append(_finding("tracking-pixel", "info", "Remote images and tracking pixels",
                          f"{imgs['remote']} remote image(s) from {', '.join(imgs['remote_hosts'][:3]) or 'other servers'}"
                          + (f"; {imgs['tracking_pixels']} look like tracking pixels" if imgs.get("tracking_pixels") else "")
                          + ". Loading them tells the sender the message was opened."))
    return F


QR_SUBJECT = re.compile(r"\bqr[\s-]?code\b|\bscan\b.{0,20}\b(code|qr)\b", re.IGNORECASE)


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:?#\s]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _looks_ip(text: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(text.split("]")[0].strip("[").replace("IPv6:", ""))
        return True
    except ValueError:
        return False


def _idna(domain: str) -> str:
    try:
        return f"{domain} = {domain.encode('ascii').decode('idna')}"
    except Exception:
        return domain


def _human(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(round(seconds))
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if s >= size or (unit == "s" and not parts):
            parts.append(f"{s // size}{unit}")
            s %= size
    return " ".join(parts[:2])
