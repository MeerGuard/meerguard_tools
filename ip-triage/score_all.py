#!/usr/bin/env python3
import argparse
import csv
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from score import score_asn

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "reports")


def read_hosters(path: str) -> list:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p for p in line.replace("\t", " ").split() if p]
            if not parts:
                continue
            asn_str = parts[0]
            if not asn_str.isdigit():
                continue
            name = parts[1] if len(parts) > 1 else f"as{asn_str}"
            note = " ".join(parts[2:]) if len(parts) > 2 else ""
            rows.append((int(asn_str), name, note))
    return rows


def one(asn: int, name: str, note: str) -> dict:
    try:
        r = score_asn(asn)
        return {
            "asn": asn,
            "name": name,
            "note": note,
            "ok": True,
            "verdict": r["verdict"],
            "hostile": r["hostile_asn"],
            "prefixes_v4": r["prefixes_v4"],
            "total_v4": r["total_v4_addresses"],
            "black_pct": r["black_pct_union"],
            "black_hits": r["black_hits_union"],
            "white_pct": r["white_pct_mobile"],
            "white_hits": r["white_hits"].get("mobile", 0),
            "source": r["source"],
        }
    except Exception as e:
        return {"asn": asn, "name": name, "note": note, "ok": False, "error": str(e)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=os.path.join(HERE, "hosters.txt"))
    ap.add_argument("--out", default=os.path.join(REPORTS, time.strftime("%Y-%m-%d") + "-summary"))
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()

    hosters = read_hosters(args.input)
    print(f"scoring {len(hosters)} ASNs (workers={args.workers})", file=sys.stderr)
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(one, a, n, note): (a, n) for a, n, note in hosters}
        for f in as_completed(futs):
            r = f.result()
            results.append(r)
            tag = "OK  " if r["ok"] else "FAIL"
            if r["ok"]:
                print(f"  {tag} AS{r['asn']:<7} {r['name']:<18} v={r['verdict']:<12} black={r['black_pct']:>7}%  white={r['white_pct']:>7}%", file=sys.stderr)
            else:
                print(f"  {tag} AS{r['asn']:<7} {r['name']:<18} {r['error']}", file=sys.stderr)

    def sort_key(r):
        if not r["ok"]:
            return (9, 0, 0)
        if r["hostile"]:
            return (8, -r["white_pct"], r["black_pct"])
        return (r["black_pct"], -r["white_pct"], 0)
    results.sort(key=sort_key)

    csv_path = args.out + ".csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "asn", "name", "note", "ok", "verdict", "hostile", "prefixes_v4",
            "total_v4", "black_pct", "black_hits", "white_pct", "white_hits",
            "source", "error",
        ])
        w.writeheader()
        for r in results:
            w.writerow({**{k: "" for k in w.fieldnames}, **r})

    md_path = args.out + ".md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Сводка ip-triage — {time.strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write(f"Скорено ASN: **{len(results)}** ({sum(1 for r in results if r['ok'])} успешно).\n\n")
        f.write("Сортировка: сначала «чистые» (мало палёного, много белого), в конце HOSTILE-ASN и ошибки.\n\n")
        f.write("| ASN | Хостер | Вердикт | В РФ-блэке | В белом моб. | Префиксов | Всего IPv4 |\n")
        f.write("|---:|---|---|---:|---:|---:|---:|\n")
        for r in results:
            if not r["ok"]:
                f.write(f"| {r['asn']} | {r['name']} | ERROR: {r['error']} |  |  |  |  |\n")
                continue
            f.write(f"| {r['asn']} | {r['name']} | {r['verdict']} | {r['black_pct']}% | {r['white_pct']}% | {r['prefixes_v4']} | {r['total_v4']:,} |\n")
        f.write("\n## Легенда\n\n")
        f.write("- **HOSTILE-ASN** — в списке ASN, по которым ТСПУ бьёт независимо от блэклиста (Hetzner, OVH, DO, CDN77, G-Core, Akamai, Cloudflare, Amazon, Google, Azure).\n")
        f.write("- **TOXIC** — >=10% адресов уже в РФ-блэклистах.\n")
        f.write("- **WATCH** — 1-10% в РФ-блэклистах.\n")
        f.write("- **OK** — <1% в РФ-блэклистах.\n")
        f.write("- **В белом моб.** — доля адресов хостера, уже стоящих в вайтлистах МТС/Мегафон/Билайн/Теле2. Чем больше — тем выше шанс, что новый IP заработает даже при отключении мобильного интернета.\n")

    print(f"\ndone. csv: {csv_path}\n     md:  {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
