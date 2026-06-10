"""IPS: cross-platform block_attacker() via iptables / netsh."""

from __future__ import annotations

import logging
import subprocess
import sys
import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set


def _is_ipv4(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_mac(addr: str) -> bool:
    addr = addr.upper().replace("-", ":")
    parts = addr.split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)


def _block_ip_linux(ip: str) -> bool:
    try:
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            subprocess.run(["iptables", "-I", direction, "1", flag, ip, "-j", "DROP"],
                           check=True, capture_output=True)
        return True
    except Exception as e:
        logging.warning("[IPS] iptables block %s: %s", ip, e)
        return False


def _unblock_ip_linux(ip: str) -> bool:
    try:
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            subprocess.run(["iptables", "-D", direction, flag, ip, "-j", "DROP"],
                           check=False, capture_output=True)
        return True
    except Exception:
        return False


def _block_ip_windows(ip: str) -> bool:
    name = f"SOC_Block_{ip.replace('.', '_')}"
    try:
        for direction in ("in", "out"):
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={name}_{direction}", f"dir={direction}", "action=block",
                            f"remoteip={ip}", "enable=yes"], check=True, capture_output=True)
        return True
    except Exception as e:
        logging.warning("[IPS] netsh block %s: %s", ip, e)
        return False


def _unblock_ip_windows(ip: str) -> bool:
    name = f"SOC_Block_{ip.replace('.', '_')}"
    try:
        for direction in ("in", "out"):
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={name}_{direction}"], check=False, capture_output=True)
        return True
    except Exception:
        return False


class ActiveResponse:
    def __init__(self, config_loader: Callable[[], dict],
                 on_block: Optional[Callable[[dict], None]] = None):
        self._cfg = config_loader
        self._on_block = on_block
        self._lock = threading.Lock()
        self.blocked_ips: Set[str] = set()
        self.blocked_macs: Set[str] = set()
        self.ignored: Set[str] = set()
        self.block_history: List[dict] = []

    def block_attacker(self, target: str, reason: str = "", severity: str = "HIGH",
                       threat_type: str = "IPS_BLOCK", use_firewall: Optional[bool] = None) -> dict:
        import logging
        logging.info(f"[ActiveResponse] block_attacker вызван для target={target}, reason={reason}")
        target = target.strip()
        if target in self.ignored:
            logging.warning(f"[ActiveResponse] target={target} в ignored!")
            return {"ok": False, "target": target, "reason": "ignored"}
        cfg = self._cfg()
        fw = use_firewall if use_firewall is not None else cfg.get("auto_block_firewall", False)
        kind = "mac" if _is_mac(target) else ("ip" if _is_ipv4(target) else "unknown")
        logging.info(f"[ActiveResponse] kind={kind}, fw={fw}")
        with self._lock:
            if kind == "ip":
                self.blocked_ips.add(target)
                logging.info(f"[ActiveResponse] Добавили {target} в self.blocked_ips! Теперь blocked_ips: {self.blocked_ips}")
            elif kind == "mac":
                self.blocked_macs.add(target.upper().replace("-", ":"))
                logging.info(f"[ActiveResponse] Добавили {target} в self.blocked_macs!")
            else:
                logging.warning(f"[ActiveResponse] target={target} не является IP или MAC!")
                return {"ok": False, "target": target, "kind": kind}
        firewall_ok = False
        if fw and kind == "ip":
            firewall_ok = _block_ip_windows(target) if sys.platform == "win32" else _block_ip_linux(target)
            logging.info(f"[ActiveResponse] firewall_ok={firewall_ok}")
        rec = {"time": datetime.now().strftime("%H:%M:%S"), "type": threat_type,
               "target": target, "kind": kind, "severity": severity,
               "reason": reason or "IPS auto-block", "firewall": firewall_ok}
        with self._lock:
            self.block_history.append(rec)
            if len(self.block_history) > 500:
                self.block_history = self.block_history[-300:]
        if self._on_block:
            try:
                self._on_block(rec)
                logging.info(f"[ActiveResponse] Вызвали _on_block")
            except Exception:
                logging.exception("[ActiveResponse] _on_block ошибка")
        return {"ok": True, **rec}

    def unblock_target(self, target: str) -> bool:
        target = target.strip()
        cfg = self._cfg()
        with self._lock:
            if _is_ipv4(target):
                self.blocked_ips.discard(target)
                if cfg.get("auto_block_firewall", False):
                    _unblock_ip_windows(target) if sys.platform == "win32" else _unblock_ip_linux(target)
                return True
            mac = target.upper().replace("-", ":")
            if _is_mac(mac):
                self.blocked_macs.discard(mac)
                return True
        return False

    def ignore_target(self, target: str):
        with self._lock:
            self.ignored.add(target.strip())

    def is_blocked(self, target: str) -> bool:
        t = target.strip()
        if _is_ipv4(t):
            return t in self.blocked_ips
        return t.upper().replace("-", ":") in self.blocked_macs

    def get_snapshot(self) -> dict:
        cfg = self._cfg()
        with self._lock:
            return {"mode": "IPS" if cfg.get("auto_block") else "IDS",
                    "firewall_enabled": cfg.get("auto_block_firewall", False),
                    "blocked_ips": sorted(self.blocked_ips),
                    "blocked_macs": sorted(self.blocked_macs),
                    "recent_blocks": list(self.block_history[-20:])}
