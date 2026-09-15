#!/usr/bin/env python3
"""
Какие сети страны попадают в белый мобильный список РФ.

Белый список (data/whitelist_mobile_hxehex.lst) пересекается с адресами, зарегистрированными
в стране по RIPE delegated stats, и группируется по ASN (RIPEstat network-info / as-overview).

Ограничение: delegated-страна — это страна регистрации LIR, а не дата-центра. Хостинг,
зарегистрированный в другой стране, сюда не попадёт; для него — country_score.py по ASN.

    python country_whitelist.py FI out.json
"""
import argparse
import bisect
import collections
import ipaddress
import json
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from score import load_cidrs  # noqa: E402

UA = {"User-Agent": "meerguard-ip-triage/1.0"}
DELEGATED = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"


def get(url, raw=False, tries=4):
    err = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
                b = r.read()
                return b.decode("utf-8", "replace") if raw else json.loads(b)
        except Exception as e:  # сеть/лимиты RIPEstat
            err = e
            time.sleep(2 + 3 * i)
    raise err


def main() -> int:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("cc", help="код страны ISO2, напр. FI")
    ap.add_argument("out", help="куда сохранить JSON")
    ap.add_argument("--cap", type=int, default=1000, help="максимум белых CIDR для разметки ASN")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    cc = a.cc.upper()

    wl = load_cidrs(os.path.join(HERE, "data", "whitelist_mobile_hxehex.lst"))
    ranges = []
    for line in get(DELEGATED, raw=True).splitlines():
        p = line.split("|")
        if len(p) >= 7 and p[1] == cc and p[2] == "ipv4" and p[6] in ("allocated", "assigned"):
            s = int(ipaddress.IPv4Address(p[3]))
            ranges.append((s, s + int(p[4]) - 1))
    ranges.sort()
    starts = [x for x, _ in ranges]

    def in_cc(n):
        f = int(n.network_address)
        i = bisect.bisect_right(starts, f) - 1
        return i >= 0 and ranges[i][1] >= f

    hits = [n for n in wl if in_cc(n)]
    print(f"{cc}: белых CIDR всего {len(wl)}, в адресах страны {len(hits)}, "
          f"адресов {sum(n.num_addresses for n in hits)}", file=sys.stderr)
    if len(hits) > a.cap:
        print(f"разметка ASN только для первых {a.cap} CIDR (--cap)", file=sys.stderr)

    def info(n):
        ip = str(n.network_address + (1 if n.num_addresses > 1 else 0))
        try:
            ni = get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}")["data"]
            return str(n), (ni["asns"][0] if ni["asns"] else "?")
        except Exception:
            return str(n), "err"

    with ThreadPoolExecutor(a.workers) as ex:
        rows = list(ex.map(info, hits[: a.cap]))

    agg = collections.defaultdict(lambda: {"addrs": 0, "cidrs": []})
    sizes = {str(n): n.num_addresses for n in hits}
    for c, asn in rows:
        agg[asn]["addrs"] += sizes[c]
        agg[asn]["cidrs"].append(c)
    names = {}
    for asn in agg:
        if asn in ("?", "err"):
            continue
        try:
            names[asn] = get(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}")["data"]["holder"]
        except Exception:
            names[asn] = "?"

    out = [{"asn": asn, "name": names.get(asn, ""), "wl_addrs": v["addrs"],
            "wl_cidrs": len(v["cidrs"]), "sample": v["cidrs"][:5]}
           for asn, v in sorted(agg.items(), key=lambda x: -x[1]["addrs"])]
    json.dump({"cc": cc, "whitelist_cidrs_in_cc": len(hits), "asns": out},
              open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    for r in out[:60]:
        print(f"AS{r['asn']:<8} {r['name'][:48]:48} {r['wl_addrs']:>8} адр / {r['wl_cidrs']:>3} cidr  {', '.join(r['sample'][:2])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
