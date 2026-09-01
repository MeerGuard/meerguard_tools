#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import sys
import time
from collections import defaultdict

from resolve_asn import resolve

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
REPORTS = os.path.join(HERE, "reports")

BLACKLISTS_PRIMARY = [
    ("refilter", "blacklist_refilter.lst"),
    ("antifilter", "blacklist_antifilter.lst"),
]
BLACKLISTS_REFERENCE = [
    ("eduard", "blacklist_eduard.lst"),
]
BLACKLISTS = BLACKLISTS_PRIMARY + BLACKLISTS_REFERENCE
WHITELISTS = [
    ("mobile", "whitelist_mobile_hxehex.lst"),
]

HOSTILE_ASNS = {24940, 14061, 16276, 60068, 199524, 20940, 13335, 16509}


def load_cidrs(path: str) -> list:
    """Читает файл списком CIDR (по одному в строке). Толерантен к мусору."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip().split("#")[0].strip()
            if not s:
                continue
            if "/" not in s:
                s = s + "/32"
            try:
                out.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                continue
    return [n for n in out if isinstance(n, ipaddress.IPv4Network)]


def index_by_octet(nets: list) -> dict:
    """Индекс подсетей по первому октету, для быстрого overlap."""
    idx = defaultdict(list)
    for n in nets:
        first, last = int(n.network_address), int(n.broadcast_address)
        for octet in range(first >> 24, (last >> 24) + 1):
            idx[octet].append(n)
    return idx


def intersect_count(host: ipaddress.IPv4Network, blocked_idx: dict) -> int:
    """Считает адреса host, попадающие в любую подсеть из blocked_idx."""
    first, last = int(host.network_address), int(host.broadcast_address)
    covered = 0
    seen_ranges = []
    for octet in range(first >> 24, (last >> 24) + 1):
        for b in blocked_idx.get(octet, ()):
            b_first, b_last = int(b.network_address), int(b.broadcast_address)
            lo, hi = max(first, b_first), min(last, b_last)
            if lo > hi:
                continue
            seen_ranges.append((lo, hi))
    seen_ranges.sort()
    prev_hi = -1
    for lo, hi in seen_ranges:
        if lo > prev_hi:
            covered += hi - lo + 1
            prev_hi = hi
        elif hi > prev_hi:
            covered += hi - prev_hi
            prev_hi = hi
    return covered


def score_asn(asn: int) -> dict:
    asn_data = resolve(asn)
    prefixes = [ipaddress.ip_network(p, strict=False) for p in asn_data["prefixes"]]
    prefixes = [p for p in prefixes if isinstance(p, ipaddress.IPv4Network)]

    black_idx, black_stats = {}, {}
    for name, fname in BLACKLISTS:
        nets = load_cidrs(os.path.join(DATA, fname))
        black_idx[name] = index_by_octet(nets)
        black_stats[name] = len(nets)

    white_idx, white_stats = {}, {}
    for name, fname in WHITELISTS:
        nets = load_cidrs(os.path.join(DATA, fname))
        white_idx[name] = index_by_octet(nets)
        white_stats[name] = len(nets)

    total_v4 = sum(p.num_addresses for p in prefixes)
    per_prefix = []
    tot_black = {n: 0 for n, _ in BLACKLISTS}
    tot_white = {n: 0 for n, _ in WHITELISTS}

    for p in prefixes:
        row = {"prefix": str(p), "size": p.num_addresses}
        for name in tot_black:
            c = intersect_count(p, black_idx[name])
            row["black_" + name] = c
            tot_black[name] += c
        for name in tot_white:
            c = intersect_count(p, white_idx[name])
            row["white_" + name] = c
            tot_white[name] += c
        per_prefix.append(row)

    primary_names = {n for n, _ in BLACKLISTS_PRIMARY}
    black_union_idx = defaultdict(list)
    for name in black_idx:
        if name not in primary_names:
            continue
        for k, v in black_idx[name].items():
            black_union_idx[k].extend(v)
    tot_black_union = sum(intersect_count(p, black_union_idx) for p in prefixes)

    def pct(n: int) -> float:
        return round(100.0 * n / total_v4, 4) if total_v4 else 0.0

    verdict = "OK"
    black_pct = pct(tot_black_union)
    if asn in HOSTILE_ASNS:
        verdict = "HOSTILE-ASN"
    elif black_pct >= 10.0:
        verdict = "TOXIC"
    elif black_pct >= 1.0:
        verdict = "WATCH"

    return {
        "asn": asn,
        "source": asn_data["source"],
        "peeringdb": asn_data.get("peeringdb") or {},
        "hostile_asn": asn in HOSTILE_ASNS,
        "prefixes_v4": len(prefixes),
        "total_v4_addresses": total_v4,
        "blacklist_sizes": black_stats,
        "whitelist_sizes": white_stats,
        "black_hits_by_list": tot_black,
        "black_hits_union": tot_black_union,
        "black_pct_union": black_pct,
        "white_hits": tot_white,
        "white_pct_mobile": pct(tot_white.get("mobile", 0)),
        "verdict": verdict,
        "per_prefix_worst": sorted(
            per_prefix,
            key=lambda r: sum(r[k] for k in r if k in {"black_" + n for n, _ in BLACKLISTS_PRIMARY}),
            reverse=True,
        )[:15],
    }


def render_report(result: dict) -> str:
    r = result
    lines = []
    lines.append(f"# AS{r['asn']} — отчёт ip-triage")
    lines.append("")
    lines.append(f"- Дата: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- Источник префиксов: {r['source']}")
    lines.append(f"- Префиксов IPv4: {r['prefixes_v4']}")
    lines.append(f"- Всего адресов IPv4: {r['total_v4_addresses']:,}")
    lines.append(f"- В «недружественных» ASN (блок ФСБ 19.06.2025): **{'да' if r['hostile_asn'] else 'нет'}**")
    pdb = r.get("peeringdb") or {}
    if pdb:
        lines.append(f"- PeeringDB: **{pdb.get('name','?')}** ({pdb.get('aka','')})")
        lines.append(f"  - Тип: `{pdb.get('info_type','?')}` (Content/NSP/Cable/DSL/ISP/Enterprise/…)")
        lines.append(f"  - Скоп: `{pdb.get('info_scope','?')}`")
        lines.append(f"  - Трафик: `{pdb.get('info_traffic','?')}`")
        if pdb.get("website"):
            lines.append(f"  - Сайт: {pdb.get('website')}")
    else:
        lines.append("- PeeringDB: **нет записи** (хостер не участвует в точках обмена — для нас косвенно плохой знак)")
    lines.append("")
    lines.append(f"## Вердикт: **{r['verdict']}**")
    lines.append("")
    lines.append(f"- Заблокировано в РФ (refilter+antifilter): **{r['black_pct_union']}%** ({r['black_hits_union']:,} адресов)")
    lines.append(f"- В белом списке мобильных операторов: **{r['white_pct_mobile']}%** ({r['white_hits'].get('mobile', 0):,} адресов)")
    lines.append("")
    lines.append("## Разбивка по блэклистам")
    lines.append("")
    lines.append("| Список | Роль | Записей | Попало в подсети хостера |")
    lines.append("|---|---|---:|---:|")
    primary_names = {n for n, _ in BLACKLISTS_PRIMARY}
    for name, size in r["blacklist_sizes"].items():
        hit = r["black_hits_by_list"][name]
        role = "primary" if name in primary_names else "reference"
        lines.append(f"| {name} | {role} | {size:,} | {hit:,} |")
    lines.append("")
    lines.append("- **primary** — российский реестр РКН и его агрегации, попадание = реальная блокировка в РФ.")
    lines.append("- **reference** — расширенный список (РКН + санкции + CDN/cloud), справочно; попадание не означает блокировку в РФ.")
    lines.append("")
    lines.append("## Топ-15 худших подсетей")
    lines.append("")
    lines.append("| Подсеть | Размер | В РФ-блэке (primary) | В белом моб. |")
    lines.append("|---|---:|---:|---:|")
    primary_keys = {"black_" + n for n, _ in BLACKLISTS_PRIMARY}
    for row in r["per_prefix_worst"]:
        black_sum = sum(v for k, v in row.items() if k in primary_keys)
        white_sum = sum(v for k, v in row.items() if k.startswith("white_"))
        lines.append(f"| {row['prefix']} | {row['size']:,} | {black_sum:,} | {white_sum:,} |")
    lines.append("")
    lines.append("## Легенда вердиктов")
    lines.append("")
    lines.append("- **HOSTILE-ASN** — в списке ASN, по которым ТСПУ активно фильтрует независимо от блэклиста (Hetzner, OVH, DO, CDN77, G-Core, Akamai, Cloudflare, Amazon).")
    lines.append("- **TOXIC** — >=10% адресов хостера уже в чёрных списках.")
    lines.append("- **WATCH** — 1-10% адресов в чёрных списках.")
    lines.append("- **OK** — <1% в чёрных списках.")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("asn", type=int)
    ap.add_argument("--name", default=None, help="hoster short name for report filename")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    r = score_asn(args.asn)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0

    md = render_report(r)
    print(md)

    os.makedirs(REPORTS, exist_ok=True)
    tag = args.name or f"as{r['asn']}"
    path = os.path.join(REPORTS, f"{time.strftime('%Y-%m-%d')}-{tag}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"\nsaved: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
