#!/usr/bin/env python3
"""
Проверка «проходит ли с мобилки в режиме белых списков» через модемы Latency Lab
(latencylab.ru) — пять операторов: tmobile, megafon, beeline, mts, t2.

НУЖНО ТОЛЬКО для узлов под белые зоны (мост, вход в РФ). Для обычного зарубежного
хостера, доступного из РФ, не нужно — там хватает probe.py без --ll.

Модемы в ОДНОЙ точке (агент `orel`), белые списки региональные: «проходит там»,
а не «по всей РФ». Это TCP/ICMP-проба, а не туннель.

Ключ: переменная LATENCYLAB_API_KEY или строка LATENCYLAB_API_KEY=... в файле
--key-file (по умолчанию ../../MeerGuardNetwrokKnowledge/secrets.local.md).
Официальные доки: https://latencylab.ru/api.html (+ openapi.yaml).

Лимит: 100 запросов в сутки (UTC), общий с ботом и консолью. 1 цель = 1 запрос,
даже если проверять всеми пятью операторами — поэтому ping идёт через /multiscan.

⚠️ Правила сервиса запрещают сканировать чужую инфраструктуру и автоматически
обходить лимиты, а /asn-scan ключу не разрешён (ключ отозвали + бан за вызов).
Поэтому скана ASN здесь НЕТ: хостера целиком сканировать кнопкой «Скан ASN»,
пачку тест-IP — «Пинг файла» в боте @Latency_Lab_bot. Здесь — единичные цели.

Примеры:
  python latencylab.py status
  python latencylab.py ping 188.72.103.4 45.91.248.53:8443 media.normedia.cloud
  python latencylab.py subnet 188.72.103.0/24 --ops megafon
  python latencylab.py usage
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://console.latencylab.ru/api/lab"
OPS = ["tmobile", "megafon", "beeline", "mts", "t2"]
DEFAULT_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "MeerGuardNetwrokKnowledge", "secrets.local.md")
UA = "meerguard-ip-triage/1.0 (+https://github.com/MeerGuard/meerguard_tools)"

_KEY = None


def load_key(key_file: str = DEFAULT_KEY_FILE) -> str:
    global _KEY
    if _KEY:
        return _KEY
    _KEY = os.environ.get("LATENCYLAB_API_KEY", "").strip()
    if not _KEY and os.path.exists(key_file):
        with open(key_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith("LATENCYLAB_API_KEY="):
                    _KEY = line.split("=", 1)[1].strip()
                    break
    if not _KEY:
        raise RuntimeError("нет LATENCYLAB_API_KEY (переменная окружения или --key-file)")
    return _KEY


def _call(path: str, body: dict = None, timeout: int = 120) -> dict:
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        method="POST" if body is not None else "GET",
        headers={
            "Authorization": f"Bearer {load_key()}",
            "Content-Type": "application/json",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}"}


def _wait_job(req_id: str, wait: int = 600) -> dict:
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(5)
        d = _call(f"/job/{req_id}", timeout=30)
        st = d.get("status")
        if st == "done":
            return d.get("result") or {}
        if st in ("cancelled", "error") or d.get("ok") is False:
            raise RuntimeError(d.get("error") or st)
    raise RuntimeError(f"job {req_id}: не дождались за {wait} с")


def _start(path: str, body: dict) -> dict:
    """Асинхронный запуск + ожидание результата задачи."""
    d = _call(path, {**body, "async": True})
    if not d.get("ok"):
        raise RuntimeError(d.get("error"))
    if d.get("status") == "pending":
        return _wait_job(d["req_id"])
    return d.get("result") or {}


def status() -> dict:
    d = _call("/status")
    if not d.get("ok"):
        raise RuntimeError(d.get("error"))
    return d["result"]


def usage() -> dict:
    d = _call("/account/stats")
    if not d.get("ok"):
        raise RuntimeError(d.get("error"))
    return d["result"]


def _short(row: dict) -> str:
    """Строка результата: для IP — ICMP и TCP отдельно (сырой вывод ping слишком длинный)."""
    def ms(v):
        return f" {v:.0f} ms" if isinstance(v, (int, float)) else ""
    parts = []
    if row.get("icmp_ok") is not None:
        parts.append(f"ICMP {'ok' if row['icmp_ok'] else 'fail'}{ms(row.get('icmp_rtt_ms'))}")
    if row.get("tcp_ok") is not None:
        parts.append(f"TCP {'ok' if row['tcp_ok'] else 'fail'}{ms(row.get('tcp_rtt_ms'))}")
    if parts:
        return " · ".join(parts)
    return (row.get("output") or "").split("\n")[0]


def ping_all(target: str, port: int = None, ops: list = None) -> dict:
    """
    Одна цель всеми выбранными модемами через /multiscan — 1 запрос из лимита.
    target — IP или домен; port — только для IP (TCP на этот порт), домен всегда TCP.
    """
    body = {"target": target, "operators": ops or OPS}
    if port:
        body["tcp_port"] = port
    try:
        r = _start("/multiscan", body)
    except Exception as e:
        return {"tool": "latencylab", "ok": False, "error": str(e)}
    per_op = [{
        "operator": row.get("operator"),
        "ok": bool(row.get("ok")),
        "rtt_ms": row.get("rtt_ms"),
        "output": _short(row),
    } for row in r.get("results") or []]
    return {
        "tool": "latencylab",
        "ok": True,
        "target": f"{target}:{port}" if port else target,
        "alive_ops": sum(1 for p in per_op if p["ok"]),
        "total_ops": len(per_op),
        "per_op": per_op,
        "skipped": r.get("skipped_line"),
    }


def subnet_scan(cidr: str, op: str) -> dict:
    """
    Одна подсеть /24…/32 через модем оператора. Сервис сначала пингует подсеть
    «с провода», потом через модем — только живые с провода адреса; молчащие
    с провода в результат не попадают вообще.
    """
    r = _start("/subnet-scan", {"operator": op, "target": cidr})
    wire = r.get("wire_alive_count") or 0
    mob = r.get("alive_count") or 0
    return {
        "cidr": cidr,
        "operator": op,
        "wire_alive": wire,
        "mobile_alive": mob,
        "status": r.get("status_text"),
        "reachable_ips": r.get("reachable_ips") or [],
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Белые списки вживую: мобильные модемы Latency Lab. Только для узлов под белые зоны.")
    ap.add_argument("--key-file", default=DEFAULT_KEY_FILE)
    ap.add_argument("--ops", default=None, help="операторы через запятую (по умолчанию все 5; для subnet — megafon)")
    ap.add_argument("--json", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="модемы: online, WL, очередь")
    sub.add_parser("usage", help="расход суточного лимита")
    p = sub.add_parser("ping", help="IP, домен или IP:порт — всеми модемами, 1 запрос на цель")
    p.add_argument("targets", nargs="+")
    s = sub.add_parser("subnet", help="подсеть /24…/32 через один модем (свои адреса / подсеть кандидата)")
    s.add_argument("cidrs", nargs="+")
    args = ap.parse_args()
    load_key(args.key_file)

    if args.cmd in ("status", "usage"):
        r = status() if args.cmd == "status" else usage()
        if args.json or args.cmd == "usage":
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        print(f"агент: {r.get('node_id')}")
        for o in r["operators"]:
            print(f"  {o['id']:8} online={o['online']} wl={o['wl']} очередь={o['queue_count']}")
        return 0

    if args.cmd == "ping":
        ops = args.ops.split(",") if args.ops else OPS
        out = []
        for t in args.targets:
            host, _, port = t.rpartition(":")
            r = ping_all(host, int(port), ops) if port.isdigit() and host else ping_all(t, None, ops)
            out.append(r)
            if args.json:
                continue
            if not r["ok"]:
                print(f"=== {t} — ERROR {r['error']}")
                continue
            print(f"=== {r['target']} — {r['alive_ops']}/{r['total_ops']} операторов")
            for p_ in r["per_op"]:
                print(f"  [{'+' if p_['ok'] else '-'}] {p_['operator']:8} {p_['output']}")
            if r["skipped"]:
                print(f"  пропущено: {r['skipped']}")
        if args.json:
            print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    ops = args.ops.split(",") if args.ops else ["megafon"]
    rows = [subnet_scan(c, op) for c in args.cidrs for op in ops]
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    for r in rows:
        print(f"  {r['cidr']:18} {r['operator']:8} модем {r['mobile_alive']:3} / провод {r['wire_alive']:3}"
              f"  {r['status'] or ''}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
