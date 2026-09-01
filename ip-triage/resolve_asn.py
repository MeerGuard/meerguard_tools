#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cache")

RIPE_ANNOUNCED = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
IPVERSE_FALLBACK = "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{asn}/aggregated.json"
PEERINGDB_NET = "https://peeringdb.com/api/net?asn={asn}"

UA = "meerguard-ip-triage/1.0 (+https://github.com/MeerGuard/meerguard_tools)"
CACHE_TTL = 24 * 3600


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def _cache_path(asn: int) -> str:
    return os.path.join(CACHE, f"asn_{asn}.json")


def _cache_fresh(path: str) -> bool:
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) < CACHE_TTL


def peeringdb_lookup(asn: int) -> dict:
    """Классификация ASN от PeeringDB. Пустой dict если ASN не зарегистрирован."""
    try:
        j = _get_json(PEERINGDB_NET.format(asn=asn))
        arr = j.get("data") or []
        if not arr:
            return {}
        n = arr[0]
        return {
            "name": n.get("name") or "",
            "aka": n.get("aka") or "",
            "info_type": n.get("info_type") or "",
            "info_scope": n.get("info_scope") or "",
            "info_traffic": n.get("info_traffic") or "",
            "info_ratio": n.get("info_ratio") or "",
            "info_prefixes4": n.get("info_prefixes4"),
            "info_prefixes6": n.get("info_prefixes6"),
            "website": n.get("website") or "",
        }
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {}


def resolve(asn: int) -> dict:
    """
    Возвращает {'asn': N, 'source': 'ripe'|'ipverse'|'cache',
                'prefixes': [...], 'v4_count': int, 'v6_count': int,
                'peeringdb': {...} or {}}
    """
    os.makedirs(CACHE, exist_ok=True)
    cache = _cache_path(asn)

    if _cache_fresh(cache):
        with open(cache, "r", encoding="utf-8") as f:
            data = json.load(f)
            data["source"] = "cache"
            return data

    v4, v6, source = [], [], None

    try:
        j = _get_json(RIPE_ANNOUNCED.format(asn=asn))
        if j.get("status") == "ok":
            for p in j["data"]["prefixes"]:
                pfx = p["prefix"]
                (v4 if ":" not in pfx else v6).append(pfx)
            source = "ripe"
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"  ripe fail: {e}", file=sys.stderr)

    if not v4 and not v6:
        try:
            j = _get_json(IPVERSE_FALLBACK.format(asn=asn))
            v4 = list(j.get("subnets", {}).get("ipv4", []))
            v6 = list(j.get("subnets", {}).get("ipv6", []))
            source = "ipverse"
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            print(f"  ipverse fail: {e}", file=sys.stderr)

    if not v4 and not v6:
        raise RuntimeError(f"AS{asn}: no prefixes found in RIPE or ipverse")

    pdb = peeringdb_lookup(asn)
    result = {
        "asn": asn,
        "source": source,
        "prefixes": v4,
        "prefixes_v6": v6,
        "v4_count": len(v4),
        "v6_count": len(v6),
        "peeringdb": pdb,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(cache, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("asn", type=int, help="AS number (e.g. 24940)")
    ap.add_argument("--json", action="store_true", help="dump full JSON")
    args = ap.parse_args()

    r = resolve(args.asn)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        pdb = r.get("peeringdb") or {}
        pdb_line = f"  name='{pdb.get('name','')}'  type={pdb.get('info_type','?')}  scope={pdb.get('info_scope','?')}" if pdb else "  (нет в PeeringDB)"
        print(f"AS{r['asn']}  source={r['source']}  v4={r['v4_count']}  v6={r['v6_count']}")
        print(pdb_line)
        for p in r["prefixes"][:15]:
            print(f"  {p}")
        if r["v4_count"] > 15:
            print(f"  ... and {r['v4_count'] - 15} more v4 prefixes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
