#!/usr/bin/env python3
"""
Доля белых и чёрных адресов у ASN — только по префиксам, расположенным в заданной стране.

Для каждого ASN из файла кандидатов берутся IPv4-префиксы (resolve_asn), каждому префиксу
определяется гео (RIPEstat maxmind-geo-lite), оставляются префиксы страны и сверяются
с белым мобильным и чёрными списками.

Файл кандидатов: строки «ASN название», # — комментарий.

    python country_score.py FI candidates.txt out.json [--cap 800]
"""
import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from score import load_cidrs, index_by_octet, intersect_count, HOSTILE_ASNS  # noqa: E402
from resolve_asn import resolve  # noqa: E402

UA = {"User-Agent": "meerguard-ip-triage/1.0"}


def get(url, tries=4):
    err = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
                return json.loads(r.read())
        except Exception as e:
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
    ap.add_argument("cc", help="код страны ISO2")
    ap.add_argument("candidates", help="файл «ASN название»")
    ap.add_argument("out", help="куда сохранить JSON")
    ap.add_argument("--cap", type=int, default=800, help="максимум префиксов на ASN для гео")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    cc = a.cc.upper()

    d = os.path.join(HERE, "data")
    wl = index_by_octet(load_cidrs(os.path.join(d, "whitelist_mobile_hxehex.lst")))
    bl = index_by_octet(load_cidrs(os.path.join(d, "blacklist_refilter.lst"))
                        + load_cidrs(os.path.join(d, "blacklist_antifilter.lst")))
    # Справочно: полный список antifilter (грубый, /24 целиком) — в основной % не входит.
    all_path = os.path.join(d, "blacklist_antifilter_all.lst")
    bl_all = index_by_octet(load_cidrs(all_path)) if os.path.exists(all_path) else None

    def geo(p):
        try:
            locs = get(f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={p}")["data"]["located_resources"]
            return {(l["country"], l["city"] or "") for r in locs for l in r["locations"]}
        except Exception:
            return {("?", "")}

    results = []
    for line in open(a.candidates, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        asn = int(parts[0].upper().lstrip("AS"))
        name = parts[1] if len(parts) > 1 else ""
        try:
            pre = [ipaddress.ip_network(p, strict=False) for p in resolve(asn)["prefixes"]]
        except Exception as e:
            print(f"AS{asn} {name}: ошибка префиксов {e}", flush=True)
            continue
        pre = [p for p in pre if p.version == 4]
        check = sorted(pre, key=lambda p: p.num_addresses)[: a.cap]
        with ThreadPoolExecutor(a.workers) as ex:
            geos = list(ex.map(geo, check))
        local = [(p, sorted({c for k, c in g if k == cc})) for p, g in zip(check, geos) if any(k == cc for k, _ in g)]
        tot = sum(p.num_addresses for p, _ in local)
        w = sum(intersect_count(p, wl) for p, _ in local)
        b = sum(intersect_count(p, bl) for p, _ in local)
        b_all = sum(intersect_count(p, bl_all) for p, _ in local) if bl_all is not None else None
        r = {
            "asn": asn, "name": name, "hostile": asn in HOSTILE_ASNS,
            "v4_prefixes": len(pre), "geo_checked": len(check),
            "cc_prefixes": len(local), "cc_addrs": tot,
            "white_pct": round(100 * w / tot, 2) if tot else None,
            "black_pct": round(100 * b / tot, 3) if tot else None,
            "black_all_pct": round(100 * b_all / tot, 2) if tot and b_all is not None else None,
            "cc_list": [(str(p), c, intersect_count(p, wl), intersect_count(p, bl)) for p, c in local][:60],
        }
        results.append(r)
        print(f"AS{asn} {name}: v4 {len(pre)} (гео по {len(check)}), {cc}-префиксов {len(local)}, адресов {tot}, "
              f"белых {r['white_pct']}%, чёрных {r['black_pct']}% (справочно antifilter-all {r['black_all_pct']}%)"
              f"{'  HOSTILE' if r['hostile'] else ''}", flush=True)
    json.dump({"cc": cc, "results": results}, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
