#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "meerguard-ip-triage/1.0 (+https://github.com/MeerGuard/meerguard_tools)"

CHECK_HOST_NODES = ["ru1.node.check-host.net", "ru2.node.check-host.net", "ru3.node.check-host.net"]
CHECK_HOST_URL = ("https://check-host.net/check-tcp?host={target}"
                  "&node=ru1.node.check-host.net"
                  "&node=ru2.node.check-host.net"
                  "&node=ru3.node.check-host.net")
CHECK_RESULT_URL = "https://check-host.net/check-result/{req_id}"

GLOBALPING_URL = "https://api.globalping.io/v1/measurements"


def _get_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _post_json(url: str, payload: dict, timeout: int = 30) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def check_host_tcp(ip: str, port: int = 443, wait: int = 12) -> dict:
    target = f"{ip}:{port}"
    submit_url = CHECK_HOST_URL.format(target=urllib.parse.quote(target))
    try:
        r = _get_json(submit_url)
    except Exception as e:
        return {"tool": "check-host", "ok": False, "error": f"submit: {e}"}
    req_id = r.get("request_id")
    if not req_id:
        return {"tool": "check-host", "ok": False, "error": f"no request_id: {r}"}

    result_url = CHECK_RESULT_URL.format(req_id=req_id)
    deadline = time.time() + wait
    result = None
    while time.time() < deadline:
        time.sleep(2)
        try:
            result = _get_json(result_url)
        except Exception:
            continue
        if result and all(v is not None for v in result.values()):
            break

    per_node = {}
    alive = 0
    total = 0
    if result:
        for node, payload in result.items():
            total += 1
            if not payload:
                per_node[node] = {"ok": None, "raw": None}
                continue
            first = payload[0] if isinstance(payload, list) else payload
            ok = isinstance(first, dict) and first.get("address") and first.get("time") is not None
            per_node[node] = {"ok": bool(ok), "raw": first}
            if ok:
                alive += 1
    return {
        "tool": "check-host",
        "ok": True,
        "target": target,
        "request_id": req_id,
        "alive_nodes": alive,
        "total_nodes": total,
        "per_node": per_node,
    }


def globalping_ping(ip: str, limit: int = 5, wait: int = 25) -> dict:
    payload = {
        "type": "ping",
        "target": ip,
        "locations": [{"country": "RU"}],
        "limit": limit,
        "measurementOptions": {"packets": 3},
    }
    try:
        r = _post_json(GLOBALPING_URL, payload)
    except Exception as e:
        return {"tool": "globalping", "ok": False, "error": f"submit: {e}"}
    mid = r.get("id")
    if not mid:
        return {"tool": "globalping", "ok": False, "error": f"no id: {r}"}

    url = f"{GLOBALPING_URL}/{mid}"
    deadline = time.time() + wait
    data = None
    while time.time() < deadline:
        time.sleep(2)
        try:
            data = _get_json(url)
        except Exception:
            continue
        if data and data.get("status") == "finished":
            break

    per_probe = []
    alive = 0
    total = 0
    if data:
        for res in data.get("results", []):
            total += 1
            probe = res.get("probe", {})
            r_ = res.get("result", {})
            stats = r_.get("stats", {}) or {}
            loss = stats.get("loss")
            ok = loss is not None and loss < 100
            per_probe.append({
                "city": probe.get("city"),
                "asn": probe.get("asn"),
                "network": probe.get("network"),
                "loss_pct": loss,
                "min_ms": stats.get("min"),
                "avg_ms": stats.get("avg"),
                "ok": ok,
            })
            if ok:
                alive += 1
    return {
        "tool": "globalping",
        "ok": True,
        "target": ip,
        "measurement_id": mid,
        "alive_probes": alive,
        "total_probes": total,
        "per_probe": per_probe,
    }


def globalping_http(ip: str, sni: str = "cloudflare.com", limit: int = 5, wait: int = 30) -> dict:
    """
    Настоящий TLS handshake через RU-пробы: HEAD на порт 443 конкретного IP
    с указанным SNI. Показывает, реально ли отвечает 443 из РФ — не пинг.
    """
    payload = {
        "type": "http",
        "target": ip,
        "locations": [{"country": "RU"}],
        "limit": limit,
        "measurementOptions": {
            "request": {"host": sni, "path": "/", "method": "HEAD"},
            "protocol": "HTTPS",
            "port": 443,
        },
    }
    try:
        r = _post_json(GLOBALPING_URL, payload)
    except Exception as e:
        return {"tool": "globalping-http", "ok": False, "error": f"submit: {e}"}
    mid = r.get("id")
    if not mid:
        return {"tool": "globalping-http", "ok": False, "error": f"no id: {r}"}

    url = f"{GLOBALPING_URL}/{mid}"
    deadline = time.time() + wait
    data = None
    while time.time() < deadline:
        time.sleep(2)
        try:
            data = _get_json(url)
        except Exception:
            continue
        if data and data.get("status") == "finished":
            break

    per_probe = []
    alive = 0
    total = 0
    if data:
        for res in data.get("results", []):
            total += 1
            probe = res.get("probe", {})
            r_ = res.get("result", {}) or {}
            timings = r_.get("timings") or {}
            status_code = r_.get("statusCode")
            tls_ok = timings.get("tls") is not None
            ok = tls_ok and status_code is not None
            per_probe.append({
                "city": probe.get("city"),
                "asn": probe.get("asn"),
                "network": probe.get("network"),
                "tls_ms": timings.get("tls"),
                "total_ms": timings.get("total"),
                "status_code": status_code,
                "error": r_.get("error") if not ok else None,
                "ok": ok,
            })
            if ok:
                alive += 1
    return {
        "tool": "globalping-http",
        "ok": True,
        "target": ip,
        "sni": sni,
        "measurement_id": mid,
        "alive_probes": alive,
        "total_probes": total,
        "per_probe": per_probe,
    }


def probe_one(ip: str, sni: str = "cloudflare.com") -> dict:
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_ch = pool.submit(check_host_tcp, ip)
        f_gp = pool.submit(globalping_ping, ip)
        f_ht = pool.submit(globalping_http, ip, sni)
        ch = f_ch.result()
        gp = f_gp.result()
        ht = f_ht.result()

    ch_alive = ch.get("alive_nodes", 0) if ch.get("ok") else 0
    ch_total = ch.get("total_nodes", 0) if ch.get("ok") else 0
    gp_alive = gp.get("alive_probes", 0) if gp.get("ok") else 0
    gp_total = gp.get("total_probes", 0) if gp.get("ok") else 0
    ht_alive = ht.get("alive_probes", 0) if ht.get("ok") else 0
    ht_total = ht.get("total_probes", 0) if ht.get("ok") else 0

    verdict = "UNKNOWN"
    if ch_total or gp_total or ht_total:
        if ch_alive == 0 and gp_alive == 0 and ht_alive == 0:
            verdict = "DEAD"
        elif ht_total and ht_alive == 0 and (ch_alive or gp_alive):
            verdict = "TLS-BLOCKED"
        elif ht_alive == ht_total and gp_alive == gp_total and ch_alive == ch_total:
            verdict = "ALIVE"
        else:
            verdict = "PARTIAL"

    return {
        "ip": ip,
        "sni": sni,
        "verdict": verdict,
        "check_host": ch,
        "globalping": gp,
        "globalping_http": ht,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Проверяет IP на доступность из РФ через check-host.net + Globalping."
    )
    ap.add_argument("ips", nargs="+", help="один или несколько IP")
    ap.add_argument("--sni", default="cloudflare.com", help="SNI для TLS handshake (по умолчанию cloudflare.com)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    all_res = []
    for ip in args.ips:
        print(f"probing {ip} (sni={args.sni}) ...", file=sys.stderr)
        r = probe_one(ip, sni=args.sni)
        all_res.append(r)
        if args.json:
            continue
        print(f"\n=== {ip} — {r['verdict']} ===")
        ch = r["check_host"]
        gp = r["globalping"]
        ht = r["globalping_http"]
        if ch.get("ok"):
            print(f"  check-host TCP: {ch['alive_nodes']}/{ch['total_nodes']} RU-ноды отвечают")
            for node, val in ch["per_node"].items():
                mark = "+" if val["ok"] else ("?" if val["ok"] is None else "-")
                raw = val.get("raw") or {}
                t = raw.get("time") if isinstance(raw, dict) else None
                print(f"     [{mark}] {node}: {t} s" if t else f"     [{mark}] {node}")
        else:
            print(f"  check-host TCP: ERROR {ch.get('error')}")
        if gp.get("ok"):
            print(f"  globalping ping: {gp['alive_probes']}/{gp['total_probes']} RU-проб отвечают")
            for p in gp["per_probe"]:
                mark = "+" if p["ok"] else "-"
                print(f"     [{mark}] {p['city']} AS{p['asn']} {p['network']}  loss={p['loss_pct']}%  avg={p['avg_ms']}ms")
        else:
            print(f"  globalping ping: ERROR {gp.get('error')}")
        if ht.get("ok"):
            print(f"  globalping HTTPS: {ht['alive_probes']}/{ht['total_probes']} TLS-handshake прошёл")
            for p in ht["per_probe"]:
                mark = "+" if p["ok"] else "-"
                if p["ok"]:
                    print(f"     [{mark}] {p['city']} AS{p['asn']} {p['network']}  status={p['status_code']}  tls={p['tls_ms']}ms")
                else:
                    print(f"     [{mark}] {p['city']} AS{p['asn']} {p['network']}  err={p.get('error')}")
        else:
            print(f"  globalping HTTPS: ERROR {ht.get('error')}")

    if args.json:
        print(json.dumps(all_res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
