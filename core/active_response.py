"""IPS: cross-platform block_attacker() via iptables / netsh."""

from __future__ import annotations

import logging
import re
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


def _normalize_target(target: str) -> str:
    if not target:
        return ""
    target = target.strip()
    ipv4_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", target)
    if ipv4_match:
        return ipv4_match.group(1)
    mac = target.upper().replace("-", ":")
    if _is_mac(mac):
        return mac
    return target


def _block_ip_linux(ip: str) -> bool:
    try:
        import logging
        logging.info(f"[IPS] _block_ip_linux для {ip}")
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            cmd = ["iptables", "-I", direction, "1", flag, ip, "-j", "DROP"]
            logging.info(f"[IPS] Выполняем: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=True, capture_output=True)
            logging.info(f"[IPS] Результат: {result.stdout.decode('utf-8', errors='ignore') if result.stdout else 'OK'}")
        logging.info(f"[IPS] Успешно заблокировали {ip} в Linux iptables")
        return True
    except Exception as e:
        logging.warning("[IPS] iptables block %s: %s", ip, e)
        return False


def _unblock_ip_linux(ip: str) -> bool:
    try:
        import logging
        logging.info(f"[IPS] _unblock_ip_linux для {ip}")
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            cmd = ["iptables", "-D", direction, flag, ip, "-j", "DROP"]
            logging.info(f"[IPS] Выполняем: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=False, capture_output=True)
            logging.info(f"[IPS] Результат: {result.stdout.decode('utf-8', errors='ignore') if result.stdout else 'OK'}")
        logging.info(f"[IPS] Разблокировали {ip} из Linux iptables")
        return True
    except Exception as e:
        logging.warning("[IPS] iptables unblock %s: %s", ip, e)
        return False


def _block_ip_windows(ip: str) -> bool:
    name = f"SOC_Block_{ip.replace('.', '_')}"
    try:
        import logging
        logging.info(f"[IPS] _block_ip_windows для {ip}, имя правила: {name}")
        for direction in ("in", "out"):
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={name}_{direction}", f"dir={direction}", "action=block",
                   f"remoteip={ip}", "enable=yes"]
            logging.info(f"[IPS] Выполняем: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=True, capture_output=True)
            logging.info(f"[IPS] Результат: {result.stdout.decode('utf-8', errors='ignore') if result.stdout else 'OK'}")
        logging.info(f"[IPS] Успешно заблокировали {ip} в Windows firewall")
        return True
    except Exception as e:
        logging.warning("[IPS] netsh block %s: %s", ip, e)
        return False


def _unblock_ip_windows(ip: str) -> bool:
    name = f"SOC_Block_{ip.replace('.', '_')}"
    try:
        import logging
        logging.info(f"[IPS] _unblock_ip_windows для {ip}, имя правила: {name}")
        for direction in ("in", "out"):
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
                   f"name={name}_{direction}"]
            logging.info(f"[IPS] Выполняем: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=False, capture_output=True)
            logging.info(f"[IPS] Результат: {result.stdout.decode('utf-8', errors='ignore') if result.stdout else 'OK'}")
        logging.info(f"[IPS] Разблокировали {ip} из Windows firewall")
        return True
    except Exception as e:
        logging.warning("[IPS] netsh unblock %s: %s", ip, e)
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
        logging.info(f"[ActiveResponse] block_attacker вызван для target={target}, reason={reason}, use_firewall={use_firewall}")
        target = _normalize_target(target)
        if target in self.ignored:
            logging.warning(f"[ActiveResponse] target={target} в ignored!")
            return {"ok": False, "target": target, "reason": "ignored"}
        cfg = self._cfg()
        fw = use_firewall if use_firewall is not None else cfg.get("auto_block_firewall", False)
        logging.info(f"[ActiveResponse] use_firewall={use_firewall}, auto_block_firewall={cfg.get('auto_block_firewall', False)}, итоговое fw={fw}")
        kind = "mac" if _is_mac(target) else ("ip" if _is_ipv4(target) else "unknown")
        logging.info(f"[ActiveResponse] kind={kind}, fw={fw}")
        
        # Check if already blocked first!
        with self._lock:
            if (kind == "ip" and target in self.blocked_ips) or (kind == "mac" and target.upper().replace("-", ":") in self.blocked_macs):
                logging.info(f"[ActiveResponse] target={target} уже заблокирован!")
                return {"ok": True, "target": target, "kind": kind, "reason": "already blocked"}
        
        firewall_ok = False
        if fw and kind == "ip":
            import sys
            logging.info(f"[ActiveResponse] Применяем firewall правило для {target} на платформе {sys.platform}")
            firewall_ok = _block_ip_windows(target) if sys.platform == "win32" else _block_ip_linux(target)
            logging.info(f"[ActiveResponse] firewall_ok={firewall_ok}, target={target}")
            if not firewall_ok:
                logging.warning(f"[ActiveResponse] firewall block failed for target={target}")
                return {"ok": False, "target": target, "kind": kind, "reason": "firewall_failed", "firewall": False}
        else:
            logging.info(f"[ActiveResponse] Firewall НЕ применяется: fw={fw}, kind={kind} (требуется fw=True и kind=ip)")

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
        target = _normalize_target(target)
        logging.info(f"[ActiveResponse] unblock_target вызван для target={target}")
        cfg = self._cfg()
        with self._lock:
            if _is_ipv4(target):
                logging.info(f"[ActiveResponse] target={target} это IPv4, разблокируем")
                self.blocked_ips.discard(target)
                logging.info(f"[ActiveResponse] Удалили {target} из blocked_ips. Теперь blocked_ips: {self.blocked_ips}")
                if cfg.get("auto_block_firewall", False):
                    logging.info(f"[ActiveResponse] auto_block_firewall=True, вызваем unblock в firewall")
                    result = _unblock_ip_windows(target) if sys.platform == "win32" else _unblock_ip_linux(target)
                    logging.info(f"[ActiveResponse] firewall unblock результат: {result}")
                    return result
                logging.info(f"[ActiveResponse] auto_block_firewall=False, просто удалили из списка")
                return True
            mac = target.upper().replace("-", ":")
            if _is_mac(mac):
                logging.info(f"[ActiveResponse] target={target} это MAC, разблокируем")
                self.blocked_macs.discard(mac)
                logging.info(f"[ActiveResponse] Удалили {mac} из blocked_macs. Теперь blocked_macs: {self.blocked_macs}")
                return True
            logging.warning(f"[ActiveResponse] target={target} не является IP или MAC!")
        return False

    def ignore_target(self, target: str):
        target_clean = _normalize_target(target)
        logging.info(f"[ActiveResponse] ignore_target вызван для target={target_clean}")
        with self._lock:
            self.ignored.add(target_clean)
            logging.info(f"[ActiveResponse] Добавили {target_clean} в ignored. Теперь ignored: {self.ignored}")

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
