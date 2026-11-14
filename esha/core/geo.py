"""Offline IP enrichment using MaxMind GeoLite2 databases.

Databases are looked up in ``$ESHA_GEOIP_DIR`` (if set) and then in the
bundled ``esha/static/data`` folder. Country is bundled; drop
``GeoLite2-City.mmdb`` and/or ``GeoLite2-ASN.mmdb`` next to it (see
``scripts/update_geoip.py``) to unlock city and network-owner lookups.
"""
from __future__ import annotations

import os
from functools import cache, lru_cache
from pathlib import Path

from .received import is_public_ip

try:
    import maxminddb
except Exception:  # pragma: no cover
    maxminddb = None

BUNDLED = Path(__file__).resolve().parent.parent / "static" / "data"


def _search_dirs() -> list[Path]:
    dirs = []
    if os.environ.get("ESHA_GEOIP_DIR"):
        dirs.append(Path(os.environ["ESHA_GEOIP_DIR"]))
    dirs.append(BUNDLED)
    return dirs


@cache
def _reader(kind: str):
    if maxminddb is None:
        return None
    for d in _search_dirs():
        path = d / f"GeoLite2-{kind}.mmdb"
        if path.is_file():
            try:
                # MODE_MEMORY works everywhere, including Pyodide in the browser (no mmap).
                return maxminddb.open_database(str(path), maxminddb.MODE_MEMORY)
            except Exception:
                continue
    return None


def database_info() -> dict:
    info = {}
    for kind in ("Country", "City", "ASN"):
        r = _reader(kind)
        if r is not None:
            md = r.metadata()
            info[kind.lower()] = {"build_epoch": md.build_epoch, "type": md.database_type}
    return info


@lru_cache(maxsize=4096)
def lookup(ip: str | None) -> dict | None:
    if not ip or not is_public_ip(ip):
        return None
    out: dict = {}
    city = _reader("City")
    country = _reader("Country")
    try:
        db = city if city is not None else country
        rec = db.get(ip) if db is not None else None
        if rec:
            c = rec.get("country") or rec.get("registered_country") or {}
            out.update(iso_code=(c.get("iso_code") or "").lower(), country=(c.get("names") or {}).get("en"))
            if city is not None:
                loc = rec.get("location") or {}
                out.update(city=((rec.get("city") or {}).get("names") or {}).get("en"),
                           latitude=loc.get("latitude"), longitude=loc.get("longitude"))
    except Exception:
        pass
    asn = _reader("ASN")
    if asn is not None:
        try:
            a = asn.get(ip) or {}
            out.update(asn=a.get("autonomous_system_number"), as_org=a.get("autonomous_system_organization"))
        except Exception:
            pass
    return {k: v for k, v in out.items() if v} or None
