"""Domain helpers: organizational-domain lookup, address parsing and
look-alike (typosquat / homoglyph) detection."""
from __future__ import annotations

import re
import unicodedata
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr

try:  # bundled, offline public-suffix list
    from publicsuffixlist import PublicSuffixList

    _PSL = PublicSuffixList()
except Exception:  # pragma: no cover - optional dependency
    _PSL = None


def decode_mime(value: str | None) -> str:
    """Decode RFC 2047 encoded-words (=?utf-8?b?...?=)."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def domain_of(address: str | None) -> str:
    if not address:
        return ""
    addr = parseaddr(address)[1] or address
    addr = addr.strip().strip("<>").rstrip(".")
    if "@" in addr:
        dom = addr.rsplit("@", 1)[1].lower().rstrip(".>")
        return dom if "." in dom else ""
    # bare domain (e.g. DKIM d= or header.from=)
    return addr.lower() if "." in addr else ""


def org_domain(domain: str) -> str:
    """Organizational domain per DMARC (public suffix + one label)."""
    domain = (domain or "").lower().strip(".")
    if not domain:
        return ""
    if _PSL is not None:
        try:
            p = _PSL.privatesuffix(domain)
            if p:
                return p
        except Exception:
            pass
    labels = domain.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def aligned(a: str, b: str) -> bool:
    return bool(a and b and org_domain(a) == org_domain(b))


def parse_mailbox(value: str | None) -> dict:
    decoded = decode_mime(value)
    name, addr = parseaddr(decoded)
    return {"raw": decoded, "name": name.strip(), "address": addr.strip(), "domain": domain_of(addr)}


def parse_mailbox_list(value: str | None) -> list[dict]:
    decoded = decode_mime(value)
    out = []
    for name, addr in getaddresses([decoded]):
        if addr or name:
            out.append({"name": name.strip(), "address": addr.strip(), "domain": domain_of(addr)})
    return out


# --- Look-alike detection ---------------------------------------------------

BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office365": "office.com",
    "outlook": "outlook.com", "apple": "apple.com", "icloud": "icloud.com",
    "amazon": "amazon.com", "google": "google.com", "gmail": "gmail.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "linkedin": "linkedin.com",
    "netflix": "netflix.com", "dropbox": "dropbox.com", "docusign": "docusign.net",
    "adobe": "adobe.com", "chase": "chase.com", "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com", "citibank": "citibank.com", "hsbc": "hsbc.com",
    "dhl": "dhl.com", "fedex": "fedex.com", "ups": "ups.com", "usps": "usps.com",
    "coinbase": "coinbase.com", "binance": "binance.com", "github": "github.com",
    "zoom": "zoom.us", "slack": "slack.com", "salesforce": "salesforce.com",
    "intuit": "intuit.com", "quickbooks": "intuit.com", "stripe": "stripe.com",
    "wetransfer": "wetransfer.com", "sharepoint": "microsoft.com", "onedrive": "microsoft.com",
    "aramex": "aramex.com", "emirates": "emirates.com", "stc": "stc.com.sa",
    "alrajhi": "alrajhibank.com.sa", "snb": "alahli.com", "qnb": "qnb.com",
}

# Legitimate domains that contain a brand name but are not its primary domain.
LEGIT_EXTRA = {
    "amazonses.com", "amazonaws.com", "amazon.co.uk", "microsoftonline.com", "office365.com",
    "microsoft365.com", "outlook.office365.com", "googlemail.com", "google.co.uk", "youtube.com",
    "paypal-communication.com", "paypal-corp.com", "linkedinmail.com", "facebookmail.com",
    "appleid.apple.com", "docusign.com", "githubusercontent.com", "zoom.com", "slackhq.com",
    "salesforce.com", "exacttarget.com", "netflix.net", "dropboxmail.com", "adobesign.com",
    "dhl.de", "fedex.com", "ups.com", "stripe.network", "alrajhibank.com.sa",
}

FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com",
    "gmx.net", "proton.me", "protonmail.com", "zoho.com", "yandex.com", "yandex.ru",
    "mail.ru", "qq.com", "163.com", "tutanota.com", "fastmail.com",
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "|": "l", "i": "l"})


# Common Cyrillic / Greek / other confusables -> Latin (subset of Unicode TR39).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ν": "v", "ο": "o", "ρ": "p", "α": "a", "τ": "t", "κ": "k",
    "ι": "i", "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
    "Τ": "t", "Χ": "x", "Υ": "y", "Ζ": "z", "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o",
    "Р": "p", "С": "c", "Т": "t", "Х": "x", "ⅼ": "l", "ı": "i", "ꞁ": "l", "ɑ": "a", "ս": "u", "օ": "o", "ց": "g",
})


def _skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKD", label.translate(_CONFUSABLES))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    s = s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return s.translate(_HOMOGLYPHS).replace("-", "")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_brand(domain: str) -> dict | None:
    """Return {"brand", "legit_domain", "reason"} if ``domain`` imitates a
    well-known brand without being one of its domains."""
    domain = (domain or "").lower()
    if not domain:
        return None
    org = org_domain(domain)
    label = org.split(".")[0]
    try:
        unicode_label = label.encode("ascii").decode("idna") if label.startswith("xn--") else label
    except Exception:
        unicode_label = label
    sk = _skeleton(unicode_label)
    for brand, legit in BRANDS.items():
        if org == org_domain(legit) or org.startswith(brand + ".") or org in LEGIT_EXTRA:
            continue
        if sk == _skeleton(brand) and unicode_label != brand:
            return {"brand": brand, "legit_domain": legit, "reason": "homoglyph"}
        if len(brand) >= 5 and _levenshtein(sk, _skeleton(brand)) == 1:
            return {"brand": brand, "legit_domain": legit, "reason": "typo"}
        # brand embedded with extra words: paypal-secure-login.com, microsoftonline-support.net
        if len(brand) >= 5 and brand in re.sub(r"[^a-z]", "", sk) and label != brand:
            plain = brand in re.sub(r"[^a-z]", "", unicode_label)
            return {"brand": brand, "legit_domain": legit, "reason": "embedded" if plain else "homoglyph"}
    return None


BRAND_LABEL = {
    "paypal": "PayPal", "linkedin": "LinkedIn", "github": "GitHub", "docusign": "DocuSign",
    "wetransfer": "WeTransfer", "onedrive": "OneDrive", "sharepoint": "SharePoint", "icloud": "iCloud",
    "dhl": "DHL", "ups": "UPS", "usps": "USPS", "hsbc": "HSBC", "qnb": "QNB", "snb": "SNB", "stc": "STC",
    "fedex": "FedEx", "office365": "Office 365", "quickbooks": "QuickBooks", "bankofamerica": "Bank of America",
    "wellsfargo": "Wells Fargo", "alrajhi": "Al Rajhi", "youtube": "YouTube",
}


def brand_label(brand: str) -> str:
    return BRAND_LABEL.get(brand, brand.title())


def brand_in_text(text: str) -> str | None:
    t = re.sub(r"[^a-z0-9 ]", " ", (text or "").lower())
    words = set(t.split())
    compact = t.replace(" ", "")
    for brand in BRANDS:
        if brand in words or (len(brand) >= 6 and brand in compact):
            return brand
    return None


def is_punycode(domain: str) -> bool:
    domain = domain or ""
    return not domain.isascii() or any(lbl.startswith("xn--") for lbl in domain.split("."))


def cousin_domain(candidate: str, reference: str) -> bool:
    """True if ``candidate`` is a different organisation whose name imitates
    ``reference`` (e.g. acmecorp-hr.com vs acme-corp.com, acme-c0rp.com)."""
    if not candidate or not reference or aligned(candidate, reference):
        return False
    a = _skeleton(org_domain(candidate).split(".")[0])
    b = _skeleton(org_domain(reference).split(".")[0])
    if len(b) < 4 or org_domain(reference) in FREE_MAIL or org_domain(candidate) in FREE_MAIL:
        return False
    if a == b:
        return True  # same name, different TLD or homoglyphs
    if len(b) >= 5 and b in a:
        return True  # reference name embedded: acmecorphr
    return len(b) >= 6 and _levenshtein(a, b) <= max(1, len(b) // 8)
