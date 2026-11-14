"""Offline IP enrichment using MaxMind GeoLite2 databases.

Databases are looked up in ``$MHA_GEOIP_DIR`` (if set) and then in the
bundled ``mha/static/data`` folder. Country is bundled; drop
``GeoLite2-City.mmdb`` and/or ``GeoLite2-ASN.mmdb`` next to it (see
``scripts/update_geoip.py``) to unlock city and network-owner lookups.
"""
from __future__ import annotations

import os
from functools import cache, lru_cache
from pathlib import Path

from .received import is_public_ip

try:
    import geoip2.database
    import geoip2.errors
except Exception:  # pragma: no cover
    geoip2 = None

BUNDLED = Path(__file__).resolve().parent.parent / "static" / "data"


def _search_dirs() -> list[Path]:
    dirs = []
    if os.environ.get("MHA_GEOIP_DIR"):
        dirs.append(Path(os.environ["MHA_GEOIP_DIR"]))
    dirs.append(BUNDLED)
    return dirs


@cache
def _reader(kind: str):
    if geoip2 is None:
        return None
    for d in _search_dirs():
        path = d / f"GeoLite2-{kind}.mmdb"
        if path.is_file():
            try:
                return geoip2.database.Reader(str(path))
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
        if city is not None:
            r = city.city(ip)
            out.update(
                iso_code=(r.country.iso_code or "").lower(), country=r.country.name,
                city=r.city.name, latitude=r.location.latitude, longitude=r.location.longitude,
            )
        elif country is not None:
            r = country.country(ip)
            out.update(iso_code=(r.country.iso_code or "").lower(), country=r.country.name)
    except Exception:
        pass
    asn = _reader("ASN")
    if asn is not None:
        try:
            a = asn.asn(ip)
            out.update(asn=a.autonomous_system_number, as_org=a.autonomous_system_organization)
        except Exception:
            pass
    return {k: v for k, v in out.items() if v} or None
