"""Local Wi-Fi/LAN IP detection for same-network web access."""

from __future__ import annotations

import socket
import subprocess
import sys
from typing import List, Optional


def _is_private(ip: str) -> bool:
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def get_local_ips() -> List[dict]:
    results, seen = [], set()
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            nl = name.lower()
            kind = "wifi" if any(k in nl for k in ("wi-fi", "wifi", "wlan", "беспровод")) else (
                "ethernet" if "ethernet" in nl or "eth" in nl else "other")
            for a in addrs:
                if a.family == socket.AF_INET and a.address not in ("127.0.0.1", "0.0.0.0"):
                    ip = a.address
                    if ip not in seen and _is_private(ip):
                        seen.add(ip)
                        results.append({"ip": ip, "iface": name, "type": kind})
    except Exception:
        pass
    if not results:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if _is_private(ip):
                results.append({"ip": ip, "iface": "default", "type": "wifi"})
        except Exception:
            pass
    results.sort(key=lambda x: (0 if x["type"] == "wifi" else 1, x["ip"]))
    return results


def get_primary_lan_ip() -> Optional[str]:
    ips = get_local_ips()
    return ips[0]["ip"] if ips else None


def get_connection_urls(port: int = 5000) -> List[dict]:
    seen, urls = set(), []
    for entry in get_local_ips():
        ip = entry["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        urls.append({"url": f"http://{ip}:{port}", "ip": ip, "iface": entry["iface"],
            "type": entry["type"], "label": "Wi-Fi" if entry["type"] == "wifi" else "LAN"})
    urls.sort(key=lambda u: (0 if u["ip"].startswith("192.168.") else 1, 0 if u["type"] == "wifi" else 1))
    return urls


def open_firewall_port(port: int = 5000) -> bool:
    try:
        if sys.platform == "win32":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                f"name=SOC_Sentinel_Web_{port}", "dir=in", "action=allow",
                "protocol=TCP", f"localport={port}", "profile=private"],
                check=True, capture_output=True)
        return True
    except Exception:
        return False
