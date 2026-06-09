"""
linux_firewall.py — замена Windows netsh для блокировки IP через iptables.
Вставь вызовы block_ip_linux() / unblock_ip_linux() в core/threat_engine.py
в методы block_ip() / unblock_ip() вместо Windows-специфичного кода.

Требует root (sudo) для работы iptables.
"""

import subprocess
import logging


def block_ip_linux(ip: str) -> bool:
    """Добавить правило DROP в iptables для входящего и исходящего трафика."""
    try:
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            subprocess.run(
                ["iptables", "-I", direction, "1", flag, ip, "-j", "DROP"],
                check=True, capture_output=True
            )
        logging.info(f"[iptables] Blocked {ip}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"[iptables] Failed to block {ip}: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        logging.error("[iptables] iptables not found. Run as root.")
        return False


def unblock_ip_linux(ip: str) -> bool:
    """Удалить правило DROP из iptables."""
    try:
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            subprocess.run(
                ["iptables", "-D", direction, flag, ip, "-j", "DROP"],
                check=False, capture_output=True  # check=False: не падаем если правила нет
            )
        logging.info(f"[iptables] Unblocked {ip}")
        return True
    except Exception as e:
        logging.error(f"[iptables] Failed to unblock {ip}: {e}")
        return False


def list_blocked_iptables() -> list:
    """Вернуть список заблокированных IP из iptables (только DROP-правила)."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, check=True
        )
        ips = []
        for line in result.stdout.splitlines():
            if "DROP" in line:
                parts = line.split()
                # обычно формат: num DROP all -- src dst ...
                for p in parts:
                    if p.count(".") == 3:  # простая проверка на IPv4
                        ips.append(p)
                        break
        return ips
    except Exception as e:
        logging.error(f"[iptables] list failed: {e}")
        return []
