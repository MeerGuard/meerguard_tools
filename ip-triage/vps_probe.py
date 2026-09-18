#!/usr/bin/env python3
"""
Запуск на купленной VPS (Linux).
    python3 vps_probe.py > /tmp/vps_probe.json
Забирается: scp root@vps:/tmp/vps_probe.json ./reports/vps-<ip>.json

Что делает:
  1. Определяет свой публичный IP (через api.ipify.org).
  2. IP.Check.Place — прогон готового чекера, парсинг вердикта.
  3. DNSBL Spamhaus (SBL/PBL/XBL) через DNS-запрос.
  4. Пинг до крупных RU-сайтов — характеризует связность с РФ.
  5. HTTPS-handshake до тех же RU-сайтов — работает ли исходящий 443
     (провайдер может резать зарубежным VPS).
  6. Реверс DNS (PTR) — что видно про сервер снаружи.
  7. vernette/ipregion — как гео-сервисы (Google/YouTube/ChatGPT/Netflix/
     Spotify/Steam/...) видят IP. Критично для банковских нод и AI (Gemini).
  8. Собирает всё в JSON.

Требования на VPS: bash, curl, jq (для ipregion), ping. Python 3 stdlib.
"""
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error

RU_TARGETS = ["yandex.ru", "mail.ru", "vk.com", "gosuslugi.ru", "sber.ru", "ok.ru"]
SPAMHAUS_ZONES = ["zen.spamhaus.org", "sbl.spamhaus.org", "xbl.spamhaus.org", "pbl.spamhaus.org"]
UA = "meerguard-vps-probe/1.0"


def _self_ip() -> str:
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(u, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=10) as r:
                ip = r.read().decode().strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return ip
        except Exception:
            continue
    return ""


def _ptr(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _run(cmd: list, timeout: int = 30) -> tuple:
    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")
    env.setdefault("NO_COLOR", "1")
    env.setdefault("LC_ALL", "C.UTF-8")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, "", str(e)


def ipregion() -> dict:
    """vernette/ipregion --json --group custom --ipv4"""
    cmd = "curl -sSL https://ipregion.vrnt.xyz | bash -s -- --json --ipv4"
    rc, out, err = _run(["bash", "-c", cmd], timeout=120)
    if rc != 0:
        return {"ok": False, "error": err[:400], "raw_tail": out[-400:] if out else ""}
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"json decode: {e}", "raw_tail": out[-400:]}
    services = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                services[k] = v.get("country") or v.get("region") or str(v)[:80]
            else:
                services[k] = v
    return {"ok": True, "services": services, "raw": data}


def ip_check_place() -> dict:
    """bash <(curl -Ls IP.Check.Place) -l en -4 -j -n  (json mode). Дёргает ~30 API, долгий."""
    rc, out, err = _run(
        ["bash", "-c", "curl -Ls IP.Check.Place | bash -s -- -l en -4 -j -n"],
        timeout=300,
    )
    if rc != 0:
        return {"ok": False, "error": (err or out[-500:])[:500]}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": True, "text_mode": True, "raw": out[-2000:]}
    return {"ok": True, "json": data}


def dnsbl_check(ip: str) -> dict:
    """
    Spamhaus DNSBL. Учитывает трюк: код 127.255.255.254 = query blocked
    (публичный DNS вроде 8.8.8.8 рейт-лимитится, это НЕ факт листинга).
    """
    octets = ip.split(".")
    if len(octets) != 4:
        return {"ok": False, "error": "bad ip"}
    reversed_ip = ".".join(octets[::-1])
    results = {}
    for zone in SPAMHAUS_ZONES:
        q = f"{reversed_ip}.{zone}"
        try:
            answers = socket.gethostbyname_ex(q)[2]
            if any(a == "127.255.255.254" for a in answers):
                results[zone] = {"listed": False, "rate_limited": True, "codes": answers}
            elif any(a == "127.255.255.255" for a in answers):
                results[zone] = {"listed": False, "typing_error": True, "codes": answers}
            else:
                results[zone] = {"listed": True, "codes": answers}
        except socket.gaierror:
            results[zone] = {"listed": False}
        except Exception as e:
            results[zone] = {"error": str(e)}
    listed_zones = [z for z, r in results.items() if r.get("listed")]
    rate_limited = any(r.get("rate_limited") for r in results.values())
    return {
        "ok": True,
        "listed_in": listed_zones,
        "rate_limited": rate_limited,
        "note": ("Spamhaus rate-limited public DNS — результат недостоверен, "
                 "нужен собственный резолвер или ключ.") if rate_limited else "",
        "detail": results,
    }


def ping_target(host: str, count: int = 4) -> dict:
    rc, out, err = _run(["ping", "-c", str(count), "-W", "3", host], timeout=15)
    if rc != 0:
        return {"ok": False, "error": (err or out)[:200]}
    m_loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    m_avg = re.search(r"rtt [^=]+= [^/]+/([\d.]+)/", out)
    return {
        "ok": True,
        "loss_pct": float(m_loss.group(1)) if m_loss else None,
        "avg_ms": float(m_avg.group(1)) if m_avg else None,
    }


def https_handshake(host: str, timeout: int = 8) -> dict:
    try:
        ctx = ssl.create_default_context()
        t0 = time.time()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                t_handshake = time.time() - t0
                tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while len(data) < 4096:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                status = data.split(b"\r\n", 1)[0].decode(errors="ignore") if data else ""
                return {"ok": True, "handshake_ms": round(t_handshake * 1000, 1),
                        "cipher": tls.cipher()[0], "tls_version": tls.version(), "status": status}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def collect() -> dict:
    ip = _self_ip()
    report = {
        "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ip": ip,
        "ptr": _ptr(ip) if ip else "",
        "hostname": socket.gethostname(),
    }
    if not ip:
        report["error"] = "cannot determine public ip"
        return report

    report["ip_check_place"] = ip_check_place()
    report["dnsbl_spamhaus"] = dnsbl_check(ip)
    report["ipregion"] = ipregion()

    report["ru_ping"] = {t: ping_target(t) for t in RU_TARGETS}
    report["ru_https"] = {t: https_handshake(t) for t in RU_TARGETS}

    summary = {
        "public_ip": ip,
        "spamhaus_listed_in": report["dnsbl_spamhaus"].get("listed_in", []),
        "ru_ping_alive": sum(1 for r in report["ru_ping"].values() if r.get("ok") and (r.get("loss_pct") or 0) < 100),
        "ru_https_alive": sum(1 for r in report["ru_https"].values() if r.get("ok")),
        "ru_targets_total": len(RU_TARGETS),
    }
    icp = report["ip_check_place"]
    summary["ip_check_hits"] = len(icp.get("hits", [])) if icp.get("ok") else None
    ipr = report["ipregion"]
    summary["ipregion_services"] = len(ipr.get("services", {})) if ipr.get("ok") else None
    report["summary"] = summary
    return report


def main() -> int:
    r = collect()
    json.dump(r, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    s = r.get("summary", {})
    sys.stderr.write(
        f"\n[{r.get('ip','?')}] spamhaus={s.get('spamhaus_listed_in')}  "
        f"RU-ping={s.get('ru_ping_alive')}/{s.get('ru_targets_total')}  "
        f"RU-https={s.get('ru_https_alive')}/{s.get('ru_targets_total')}  "
        f"ipcheck-hits={s.get('ip_check_hits')}  "
        f"ipregion-svc={s.get('ipregion_services')}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
