#!/usr/bin/env python3
import os
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

SOURCES = [
    ("blacklist_refilter.lst",
     "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst"),
    ("blacklist_eduard.lst",
     "https://raw.githubusercontent.com/eduard256/russia-blocked-ips/main/ip.txt"),
    ("blacklist_antifilter.lst",
     "https://antifilter.download/list/subnet.lst"),
    ("whitelist_mobile_hxehex.lst",
     "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"),
]

UA = "meerguard-ip-triage/1.0 (+https://github.com/MeerGuard/meerguard_tools)"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def main() -> int:
    os.makedirs(DATA, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] fetching {len(SOURCES)} lists into {DATA}")
    failed = 0
    for name, url in SOURCES:
        path = os.path.join(DATA, name)
        try:
            body = fetch(url)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  FAIL {name}: {e}")
            failed += 1
            continue
        with open(path, "wb") as f:
            f.write(body)
        lines = body.count(b"\n") + 1
        print(f"  OK   {name}: {len(body):>10} bytes, ~{lines} lines")
    print(f"done. failed={failed}/{len(SOURCES)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
