#!/usr/bin/env python3
"""Download the latest free MaxMind GeoLite2 databases.

1. Create a free account at https://www.maxmind.com/en/geolite2/signup
2. Generate a license key (Account > Manage License Keys)
3. Run:
       MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=xxxx python scripts/update_geoip.py

By default this downloads Country, City and ASN into mha/static/data, which
MHA picks up automatically (City adds city names, ASN adds the network owner).
Use --dest to write elsewhere and point MHA at it with MHA_GEOIP_DIR.
"""
import argparse
import base64
import io
import os
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
DEFAULT_DEST = Path(__file__).resolve().parent.parent / "mha" / "static" / "data"


def fetch(edition, account, key, dest):
    req = urllib.request.Request(URL.format(edition=edition))
    token = base64.b64encode(f"{account}:{key}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith(".mmdb"))
        src = tar.extractfile(member)
        tmp = dest / f".{edition}.mmdb.tmp"
        with open(tmp, "wb") as fh:
            shutil.copyfileobj(src, fh)
        tmp.replace(dest / f"{edition}.mmdb")
    print(f"  {edition}.mmdb updated")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    p.add_argument("--editions", default="GeoLite2-Country,GeoLite2-City,GeoLite2-ASN")
    args = p.parse_args()
    account, key = os.environ.get("MAXMIND_ACCOUNT_ID"), os.environ.get("MAXMIND_LICENSE_KEY")
    if not account or not key:
        sys.exit("Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY first (free at maxmind.com).")
    args.dest.mkdir(parents=True, exist_ok=True)
    for ed in args.editions.split(","):
        fetch(ed.strip(), account, key, args.dest)
    print(f"Done. Databases are in {args.dest}")


if __name__ == "__main__":
    main()
