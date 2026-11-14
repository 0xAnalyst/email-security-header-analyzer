"""Detection rule registry.

Every finding ESHA reports comes from one rule here. A rule has a stable ID
(``ESHA-NNN``) that never changes meaning, a default severity, optional
alternative severities that context may choose (for example "SPF passed for a
different domain" is only a note when DMARC passes), a description, remediation
advice and MITRE ATT&CK mappings.

ID ranges: 001-099 authentication, 100-199 sender identity, 200-299 routing,
300-399 message headers, 400-499 content, 500-599 spam-filter verdicts,
600-699 online enrichment, 900-999 input.

Scoring weights live in :mod:`esha.core.scoring`. A rule's ``weight`` is only
needed when it should count differently from its severity's default weight.
"""
from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info", "pass")

ATTACK = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1656": "Impersonation",
    "T1534": "Internal Spearphishing",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1027.013": "Obfuscated Files or Information: Encrypted/Encoded File",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1583.006": "Acquire Infrastructure: Web Services",
    "T1585.002": "Establish Accounts: Email Accounts",
    "T1586.002": "Compromise Accounts: Email Accounts",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1672": "Email Spoofing",
}


@dataclass(frozen=True)
class Rule:
    id: str
    key: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str = ""
    attack: tuple[str, ...] = ()
    also: tuple[str, ...] = ()  # other severities context may assign
    weight: int | None = None  # None: use the severity's weight

    @property
    def severities(self) -> tuple[str, ...]:
        return (self.severity,) + self.also

    def attack_refs(self) -> list[dict]:
        return [{"id": t, "name": ATTACK.get(t, t),
                 "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"} for t in self.attack]

    def to_dict(self) -> dict:
        return {"id": self.id, "key": self.key, "title": self.title, "severity": self.severity,
                "severities": list(self.severities), "category": self.category, "description": self.description,
                "remediation": self.remediation, "attack": self.attack_refs(), "weight": self.weight}


_SPOOF = ("T1672", "T1656")
_VERIFY = ("Confirm the request through a known channel (phone number or address you already have), "
           "not by replying or using contact details in the message.")
_LINK = "Do not open the link. Report the message, and block the domain at the mail and web gateway if it is malicious."
_FILE = "Do not open the attachment. Report the message and submit the file to your sandbox or EDR team for analysis."

_RULES = [
    # ------------------------------------------------------------ authentication
    Rule("ESHA-001", "dmarc-pass", "DMARC passed", "pass", "authentication",
         "The From domain was authenticated by SPF or DKIM aligned with it."),
    Rule("ESHA-002", "dmarc-fail", "DMARC failed", "high", "authentication",
         "Neither SPF nor DKIM authenticated the domain shown in From, so the sender may be spoofing it.",
         "Treat the From address as unverified. Check the alignment table to see which domain really sent it.",
         _SPOOF),
    Rule("ESHA-003", "dmarc-policy-none", "Sender's DMARC policy is p=none", "info", "authentication",
         "The domain owner only monitors spoofing and does not ask receivers to block it.",
         "If this is your domain, move to p=quarantine or p=reject once reports show legitimate mail aligns."),
    Rule("ESHA-004", "dmarc-missing", "No DMARC verdict", "low", "authentication",
         "No DMARC result was recorded; the sender may not publish a DMARC policy.",
         "Missing DMARC makes the From domain easy to spoof. Weigh the other findings more heavily."),
    Rule("ESHA-005", "spf-aligned", "SPF passed and aligned", "pass", "authentication",
         "The sending server is authorised for the envelope domain, which matches From."),
    Rule("ESHA-006", "spf-mismatch", "SPF passed for a different domain", "medium", "authentication",
         "SPF passed, but for an envelope domain unrelated to the From domain. Normal for mail services when DMARC "
         "passes; a common spoofing trick when it doesn't.",
         "Rely on DMARC, not SPF alone. An SPF pass only proves the server may send for the envelope domain.",
         _SPOOF, also=("info",)),
    Rule("ESHA-007", "spf-fail", "SPF failed", "high", "authentication",
         "The sending server is not authorised to send for the envelope domain.",
         "Treat the message as spoofed unless it was forwarded (forwarding breaks SPF).", _SPOOF),
    Rule("ESHA-008", "spf-softfail", "SPF soft-failed", "medium", "authentication",
         "The domain owner says the server is probably not authorised.", "", _SPOOF),
    Rule("ESHA-009", "spf-error", "SPF error", "low", "authentication",
         "The SPF record could not be evaluated (permerror or temperror)."),
    Rule("ESHA-010", "dkim-aligned", "DKIM signature valid and aligned", "pass", "authentication",
         "A valid DKIM signature from the From domain proves the message came from that domain unmodified."),
    Rule("ESHA-011", "dkim-mismatch", "DKIM signed by a different domain", "medium", "authentication",
         "The signature is valid but belongs to another domain, often a mail service. That proves who relayed "
         "the message, not who the From address claims.",
         "Check whether the signing domain is a service the sender is known to use.", _SPOOF, also=("info",)),
    Rule("ESHA-012", "dkim-fail", "DKIM failed", "medium", "authentication",
         "A DKIM signature was present but did not verify; the message may have been altered in transit.",
         "Mailing lists and forwarding can break signatures. Without that explanation, assume tampering."),
    Rule("ESHA-013", "dkim-none", "Message is not DKIM-signed", "low", "authentication",
         "No DKIM signature, so the content and From address are not cryptographically protected."),
    Rule("ESHA-014", "dkim-unverified", "DKIM signature present but no verification result", "info", "authentication",
         "The headers contain a DKIM signature but no receiving server's verification result."),
    Rule("ESHA-015", "compauth-fail", "Microsoft composite authentication failed", "high", "authentication",
         "Microsoft 365 combined SPF, DKIM, DMARC and its own signals and concluded the sender is not authentic.",
         "Microsoft's verdict is usually reliable. Check reason= codes 000 (explicit DMARC fail) and 001 (implicit).",
         _SPOOF, also=("medium",)),
    Rule("ESHA-016", "arc-broken", "ARC chain is broken", "medium", "authentication",
         "A forwarding service's authentication seal failed validation, so earlier results can't be trusted."),
    Rule("ESHA-017", "spf-conflict", "Conflicting SPF results", "low", "authentication",
         "Authentication-Results and Received-SPF disagree, which can mean an inserted or stale header."),
    Rule("ESHA-018", "forged-ar", "Authentication-Results from an unexpected server", "medium", "authentication",
         "An Authentication-Results header claims a pass but was added by a server not in the relay path. "
         "Attackers insert fake results to fool analysts and weak filters.",
         "Only trust the top-most Authentication-Results added by your own mail system.", ("T1672",)),
    Rule("ESHA-020", "dkim-from-unsigned", "DKIM signature does not cover From", "medium", "authentication",
         "The signature's h= list omits From, so the visible sender can be changed without breaking it. "
         "RFC 6376 requires From to be signed.",
         "Don't treat this signature as proof of the sender. If it is your domain, fix the signer configuration.",
         _SPOOF),
    Rule("ESHA-021", "dkim-body-length", "DKIM signature only covers part of the body (l= tag)", "medium", "authentication",
         "With l=, anyone can append content (links, forms) after the signed part and the signature still passes.",
         "Read the message as if any content after the first part is unauthenticated. Signers should not use l=.",
         ("T1672", "T1566.002")),
    Rule("ESHA-022", "dkim-few-headers", "DKIM signature covers few headers", "low", "authentication",
         "Important headers such as Subject are not signed and could have been changed after signing."),
    Rule("ESHA-023", "bimi-present", "BIMI brand logo", "info", "authentication",
         "The receiving server verified BIMI and may show the brand's logo next to the message."),
    Rule("ESHA-024", "bimi-unauthenticated", "BIMI header on unauthenticated mail", "medium", "authentication",
         "BIMI-Location or BIMI-Indicator is present but DMARC did not pass. Receivers only add these after "
         "DMARC passes, so the sender probably inserted them to borrow a brand logo.",
         "Ignore any logo shown with this message.", _SPOOF),

    # --------------------------------------------------------------- identity
    Rule("ESHA-101", "display-name-email", "Display name contains a different email address", "high", "identity",
         "The display name shows one address while the message comes from another.",
         "Look at the real address in angle brackets, not the name. " + _VERIFY, ("T1656",)),
    Rule("ESHA-102", "lookalike-sender", "Look-alike domain imitating a brand", "critical", "identity",
         "The sender's domain imitates a well-known brand with typos, look-alike characters or the brand name "
         "embedded in another domain.",
         "Block the domain and search mail logs for other messages from it.", ("T1583.001", "T1656"), also=("high",)),
    Rule("ESHA-103", "display-name-brand", "Display name claims to be a brand", "high", "identity",
         "The display name names a brand, but the address belongs to an unrelated domain.",
         _VERIFY, ("T1656",), also=("medium",)),
    Rule("ESHA-104", "sender-punycode", "Sender domain uses punycode (IDN)", "medium", "identity",
         "Internationalised domains can contain characters that look like Latin letters.", "", ("T1583.001",)),
    Rule("ESHA-105", "free-mail", "Sent from a free webmail provider", "info", "identity",
         "Free webmail accounts are easy to create; be wary if the message claims to be from a company.",
         "", ("T1585.002",)),
    Rule("ESHA-106", "from-missing", "From header missing or unparseable", "medium", "identity",
         "Legitimate mail always has a parseable From address."),
    Rule("ESHA-107", "reply-to-cousin", "Reply-To imitates the sender's domain", "critical", "identity",
         "Replies go to a domain that imitates the sender's own, the pattern of invoice and payroll fraud (BEC).",
         "Do not reply. " + _VERIFY + " Block the look-alike domain.", ("T1656", "T1583.001")),
    Rule("ESHA-108", "reply-to-mismatch", "Reply-To differs from From", "medium", "identity",
         "Replies go to a different organisation than the sender.",
         "Before replying, check that the Reply-To address belongs to the person you expect.", ("T1656",)),
    Rule("ESHA-109", "return-path-mismatch", "Return-Path differs from From", "info", "identity",
         "Bounces go to another domain, which is normal for mailing services."),
    Rule("ESHA-110", "sender-mismatch", "Sender header differs from From", "low", "identity",
         "The Sender header names another mailbox than From."),
    Rule("ESHA-120", "esp-detected", "Sent through an email service provider", "info", "identity",
         "The message was sent through a known email service provider (ESP). Envelope, DKIM and Message-ID "
         "domains belonging to that ESP are expected and explained in the other findings."),

    # ----------------------------------------------------------------- routing
    Rule("ESHA-201", "no-received", "No Received headers", "medium", "routing",
         "There is no relay path. These may not be the original headers, or the message was injected locally.",
         "Get the full original headers (Show original / View source) before drawing conclusions."),
    Rule("ESHA-202", "no-rdns", "Sending server has no reverse DNS", "low", "routing",
         "Legitimate mail servers almost always have a reverse DNS name."),
    Rule("ESHA-203", "dynamic-ip", "Sent from a residential or dynamic IP", "medium", "routing",
         "The sending address looks like a home or dynamic connection, typical of compromised machines and spam.",
         "", ("T1586.002",)),
    Rule("ESHA-204", "helo-bare-ip", "Sending server greeted with a bare IP address", "low", "routing",
         "Real mail servers normally announce their hostname."),
    Rule("ESHA-205", "clock-skew", "Clock skew between relays", "info", "routing",
         "A hop is timestamped before the previous one, usually a mis-set server clock."),
    Rule("ESHA-206", "delivery-delay", "Significant delivery delay", "info", "routing",
         "At least one hop took an hour or more."),
    Rule("ESHA-207", "no-timezone", "Timestamps without a time zone", "info", "routing",
         "Some relay timestamps have no time zone; UTC was assumed."),
    Rule("ESHA-208", "tls-all", "Encrypted in transit", "pass", "routing",
         "Every relay from a public IP used TLS."),
    Rule("ESHA-209", "tls-partial", "Some relays show no sign of TLS", "info", "routing",
         "Some public hops don't record TLS. Not proof of plain text, since not all servers log it."),

    # ---------------------------------------------------------------- message
    Rule("ESHA-301", "message-id-missing", "Message-ID missing", "medium", "message",
         "Legitimate mail servers almost always add a Message-ID."),
    Rule("ESHA-302", "message-id-mismatch", "Message-ID domain differs from From", "info", "message",
         "The Message-ID was generated by another domain's system."),
    Rule("ESHA-303", "bulk-mailer", "Bulk or scripted mailer", "low", "message",
         "The X-Mailer or User-Agent is a bulk-mail tool or script library often used by spammers."),
    Rule("ESHA-304", "urgent-subject", "Urgent or account-related wording in subject", "low", "message",
         "Urgency and account warnings are classic social-engineering pressure.", "", ("T1566",)),
    Rule("ESHA-305", "date-missing", "Date header missing", "medium", "message", "Every legitimate message has a Date."),
    Rule("ESHA-306", "date-unparseable", "Date header could not be parsed", "low", "message",
         "The Date header is malformed."),
    Rule("ESHA-307", "date-after-relay", "Date header is later than the first relay", "low", "message",
         "The message claims to be written after it was relayed, so the Date may be forged."),
    Rule("ESHA-308", "date-old", "Message was written long before it was sent", "low", "message",
         "A week or more passed between the Date and the first relay."),
    Rule("ESHA-309", "no-recipients", "No To recipients", "low", "message",
         "Recipients were hidden (Bcc or undisclosed), common in mass phishing."),
    Rule("ESHA-320", "bulk-no-unsubscribe", "Bulk mail without List-Unsubscribe", "low", "message",
         "The message is marked as bulk or list mail but has no List-Unsubscribe header. Gmail and Yahoo require "
         "one from bulk senders, so legitimate marketing almost always has it.",
         "If you don't recognise the sender, report it as spam rather than looking for an unsubscribe link."),
    Rule("ESHA-321", "unsubscribe-no-one-click", "List-Unsubscribe without one-click", "info", "message",
         "The List-Unsubscribe header has a web link but no List-Unsubscribe-Post header (RFC 8058), so mail "
         "clients can't offer a safe one-click unsubscribe."),
    Rule("ESHA-322", "fake-reply", "Subject looks like a reply, but the message isn't part of a thread", "low", "message",
         "\"RE:\" without In-Reply-To or References headers makes a first contact look like an ongoing conversation.",
         "Check your sent mail: did you ever write to this sender about this subject?", ("T1566", "T1656")),
    Rule("ESHA-323", "thread-subject-mismatch", "Thread headers with a new subject", "info", "message",
         "In-Reply-To or References point to an earlier conversation, but the subject isn't a reply or forward. "
         "Normal for many notification systems; in a personal thread it can be a sign of hijacking."),
    Rule("ESHA-324", "thread-hijack-lookalike", "Reply from a look-alike of a thread participant's domain", "high", "message",
         "The message continues an existing thread but comes from a domain that imitates one of the participants' "
         "domains, the pattern of thread hijacking after a mailbox compromise.",
         "Contact the real participant through a known channel. Check whether their mailbox was compromised.",
         ("T1534", "T1656", "T1586.002")),

    # ---------------------------------------------------------------- content
    Rule("ESHA-401", "disguised-attachment", "Disguised attachment", "critical", "content",
         "The attachment's real type is hidden by a double extension or doesn't match its name.",
         _FILE, ("T1566.001", "T1036.007", "T1204.002")),
    Rule("ESHA-402", "risky-attachment", "Risky attachment", "high", "content",
         "The attachment type can run code or open a page (HTML, scripts, executables, shortcuts, disk images, "
         "macro documents).", _FILE, ("T1566.001", "T1204.002")),
    Rule("ESHA-403", "archive-attachment", "Archive attachment", "low", "content",
         "Archives can hide their contents from some scanners."),
    Rule("ESHA-404", "credential-form", "Message contains a login or data form", "high", "content",
         "Legitimate services do not ask you to enter credentials inside an email or attachment.",
         "Do not enter anything. Report the message and reset the password if anything was submitted.",
         ("T1598.003", "T1566.001")),
    Rule("ESHA-405", "link-lookalike", "Link to a look-alike domain", "critical", "content",
         "A link points to a domain imitating a well-known brand.", _LINK, ("T1566.002", "T1583.001")),
    Rule("ESHA-406", "link-text-mismatch", "Link text does not match where it goes", "high", "content",
         "The visible link text shows one domain but the link goes to another.", _LINK, ("T1566.002", "T1204.001")),
    Rule("ESHA-407", "script-link", "Script link in message", "high", "content",
         "A javascript: or vbscript: link runs code when clicked.", _LINK, ("T1566.002", "T1204.001")),
    Rule("ESHA-408", "data-uri-link", "Link opens an embedded page", "high", "content",
         "A data: link opens a page stored inside the link itself, bypassing URL filters.",
         _LINK, ("T1566.002", "T1027.006")),
    Rule("ESHA-409", "file-share-link", "Link to a file share", "high", "content",
         "file:// or UNC links can leak Windows credentials (NTLM hashes) when opened.", _LINK, ("T1566.002",)),
    Rule("ESHA-410", "raw-ip-link", "Link points to a raw IP address", "medium", "content",
         "Legitimate services link to named domains, not raw IP addresses.", _LINK, ("T1566.002",)),
    Rule("ESHA-411", "punycode-link", "Link uses a punycode domain", "medium", "content",
         "Internationalised domains can imitate familiar names.", _LINK, ("T1566.002", "T1583.001")),
    Rule("ESHA-412", "at-in-url", "Link hides its real host after an @", "medium", "content",
         "In user@host URLs the part before @ is ignored, so the real destination is hidden.",
         _LINK, ("T1566.002",)),
    Rule("ESHA-413", "free-hosting-link", "Link to free hosting often used for phishing", "medium", "content",
         "Free hosting, form and file-sharing services are popular for short-lived phishing pages.",
         _LINK, ("T1566.002", "T1583.006")),
    Rule("ESHA-414", "shortener-link", "Shortened link hides its destination", "low", "content",
         "URL shorteners hide the real destination.", "", ("T1566.002",)),
    Rule("ESHA-415", "link-cousin", "Link to a look-alike of the sender's domain", "high", "content",
         "A link goes to a domain imitating the sender's own organisation.", _LINK, ("T1566.002", "T1583.001")),
    Rule("ESHA-416", "no-sender-links", "No links point to the sender's own domain", "info", "content",
         "All links go to other organisations. Common for marketing and redirect services."),
    Rule("ESHA-420", "html-smuggling", "HTML smuggling in attachment", "critical", "content",
         "An HTML or SVG attachment contains code that builds a file in the browser (atob, Blob, "
         "msSaveOrOpenBlob, large base64 data). This delivers malware past mail gateways.",
         _FILE + " If it was opened, check the Downloads folder and EDR telemetry on that machine.",
         ("T1027.006", "T1566.001", "T1204.002"), also=("high",)),
    Rule("ESHA-421", "encrypted-archive", "Password-protected archive", "high", "content",
         "The archive is encrypted, so mail gateways and antivirus can't inspect it. The password is usually in "
         "the message body.", _FILE, ("T1027.013", "T1566.001")),
    Rule("ESHA-422", "nested-archive", "Archive inside an archive", "medium", "content",
         "Nesting archives is a common way to slip past scanners that only unpack one level.",
         _FILE, ("T1027.013", "T1566.001")),
    Rule("ESHA-423", "risky-file-in-container", "Risky file inside archive or disk image", "critical", "content",
         "An archive or disk image contains shortcuts, scripts or programs. ISO, IMG and VHD files also bypass "
         "Windows' Mark-of-the-Web warnings.",
         _FILE, ("T1566.001", "T1553.005", "T1204.002"), also=("high",)),
    Rule("ESHA-424", "ics-external-organiser", "Calendar invite from an outside organiser", "medium", "content",
         "The invite's organiser is not the sender's domain. Calendar clients may add invites automatically, "
         "so phishers use them to get links into calendars without the message being opened.",
         "Remove the event from the calendar and report it. Don't join or open links from it.",
         ("T1566.002", "T1656")),
    Rule("ESHA-425", "ics-links", "Links in a calendar invite", "low", "content",
         "The invite description or location contains links. They are listed with the other links.",
         "", ("T1566.002",), also=("info",)),
    Rule("ESHA-426", "image-only", "Message is mostly an image", "low", "content",
         "There is almost no text, just images. Phishers use image-only mail and QR codes to hide links from "
         "filters.", "Don't scan QR codes or follow instructions in an image from an unverified sender.",
         ("T1566.002",)),
    Rule("ESHA-427", "qr-lure", "Message asks you to scan a QR code", "medium", "content",
         "QR-code phishing (quishing) moves the link to a phone, outside company protection. ESHA does not decode "
         "QR codes.", "Don't scan it. If you did and entered credentials, reset the password and revoke sessions.",
         ("T1566.002", "T1204.001"), also=("high",)),
    Rule("ESHA-428", "tracking-pixel", "Remote images and tracking pixels", "info", "content",
         "Remote images tell the sender when and where the message was opened. Normal in marketing mail."),

    # ------------------------------------------------------------------ spam
    Rule("ESHA-501", "ms-spam", "Microsoft 365 marked as spam", "medium", "spam",
         "Microsoft's spam confidence level (SCL) is 5 or higher."),
    Rule("ESHA-502", "ms-category", "Microsoft 365 phishing/spoofing category", "high", "spam",
         "Microsoft's filter classified this message as phishing, spoofing, impersonation or malware.",
         "Treat it as malicious unless the other findings clearly explain it. If it reached inboxes, check "
         "Threat Explorer for other recipients and remove the message.", ("T1566",)),
    Rule("ESHA-503", "bulk-bcl", "Bulk mail", "low", "spam", "Microsoft's bulk complaint level (BCL) is 7 or higher."),
    Rule("ESHA-504", "spamassassin", "Flagged as spam by SpamAssassin", "medium", "spam",
         "SpamAssassin's score exceeded its threshold."),

    # ------------------------------------------------------------------ input
    Rule("ESHA-900", "no-headers", "No headers found", "info", "input",
         "The input did not contain any recognisable email headers."),
]

RULES: dict[str, Rule] = {r.key: r for r in _RULES}
BY_ID: dict[str, Rule] = {r.id: r for r in _RULES}

if len(RULES) != len(_RULES) or len(BY_ID) != len(_RULES):  # pragma: no cover - guarded by tests
    raise RuntimeError("duplicate rule key or ID")


def get(key_or_id: str) -> Rule:
    return RULES.get(key_or_id) or BY_ID[key_or_id]


def all_rules() -> list[Rule]:
    return list(_RULES)
