"""
Патч для портирования SOC Sentinel с Windows 11 на Kali Linux.
Запустить: python linux_patch.py
Изменит WifiSecuritySystem.py и helpers.py на месте.
"""
import re, shutil, sys
from pathlib import Path

SRC  = Path("WifiSecuritySystem.py")
HELP = Path("utils/helpers.py")

def patch_main(text: str) -> str:
    # ── 1. Убираем Windows DPI-awareness (безопасная no-op на Linux) ──
    text = text.replace(
        "def set_dpi_awareness():\n    if sys.platform != \"win32\": return\n"
        "    try: ctypes.windll.shcore.SetProcessDpiAwareness(2)\n"
        "    except Exception:\n"
        "        try: ctypes.windll.user32.SetProcessDPIAware()\n"
        "        except Exception:\n"
        "            logging.exception(\"Error saving users file\")\n",
        "def set_dpi_awareness():\n    pass  # no-op on Linux\n"
    )

    # ── 2. Убираем проверку IsUserAnAdmin в entry-point ──
    text = re.sub(
        r"    if sys\.platform == \"win32\":\s*\n"
        r"        try:\s*\n"
        r"            if not ctypes\.windll\.shell32\.IsUserAnAdmin\(\):\s*\n"
        r"                messagebox\.showwarning\([^)]*\)\s*\n"
        r"        except Exception: pass\s*\n",
        "    # On Linux root check is done below\n"
        "    import os\n"
        "    if os.geteuid() != 0:\n"
        "        print(\"[WARNING] SOC Sentinel requires root for packet capture.\")\n"
        "        print(\"Run: sudo python WifiSecuritySystem.py\")\n",
        text,
        flags=re.MULTILINE,
    )

    # ── 3. Шрифты: убираем Windows-шрифты, ставим Linux-совместимые ──
    text = text.replace(
        'FONT_HEADER = ("Segoe UI Semibold", 13)',
        'FONT_HEADER = ("DejaVu Sans", 13)'
    )
    text = text.replace(
        'FONT_BODY   = ("Inter", 11)',
        'FONT_BODY   = ("DejaVu Sans", 11)'
    )
    text = text.replace(
        'FONT_MONO   = ("Consolas", 10)',
        'FONT_MONO   = ("DejaVu Sans Mono", 10)'
    )
    text = text.replace(
        'FONT_SMALL  = ("Inter", 9)',
        'FONT_SMALL  = ("DejaVu Sans", 9)'
    )
    text = text.replace(
        'FONT_TINY   = ("Inter", 8)',
        'FONT_TINY   = ("DejaVu Sans", 8)'
    )
    # в sidebar и UI — "Segoe UI Semibold" → "DejaVu Sans"
    text = text.replace('"Segoe UI Semibold"', '"DejaVu Sans"')
    # Consolas → DejaVu Sans Mono (все оставшиеся случаи, кроме FONT_MONO уже заменён)
    # Оставляем (\"Consolas\",N) замену аккуратно
    text = re.sub(r'"Consolas"', '"DejaVu Sans Mono"', text)

    # ── 4. ctypes — убираем прямой импорт windll, оставляем только safe-import ──
    # ctypes сам по себе кроссплатформенный, но windll — только Windows
    # Добавляем guard вокруг windll-использований (уже нет после патча п.1/2)
    # На всякий случай удалим windll-вызов если остался
    text = re.sub(r'ctypes\.windll\.[^\n]+\n', '', text)

    # ── 5. firewall auto-block: Windows netsh → Linux iptables ──
    # Ищем место где движок блокирует IP через netsh (если есть в engine)
    # В WifiSecuritySystem.py прямых netsh-вызовов нет, они в threat_engine.
    # Добавим флаг чтобы ThreatEngine знал платформу (уже кроссплатформенный).

    return text


def patch_helpers(text: str) -> str:
    """Заменяем Windows-notifier на Linux notify-send."""
    new_helpers = '''\
import threading
import sys
import subprocess
from tkinter import messagebox


def safe_len(x):
    try:
        return len(x)
    except Exception:
        return 0


def show_system_toast(title: str, message: str, severity: str = "INFO"):
    """Show a native desktop notification on Linux (notify-send) or fallback."""
    try:
        # Linux: используем notify-send (входит в libnotify)
        urgency = "critical" if severity == "CRITICAL" else "normal"
        subprocess.Popen(
            ["notify-send", "-u", urgency, title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        # notify-send не установлен — fallback в tkinter / print
        try:
            messagebox.showinfo(title, message)
        except Exception:
            print(f"{title}: {message}")
    except Exception:
        try:
            print(f"{title}: {message}")
        except Exception:
            pass
'''
    return new_helpers


def main():
    if not SRC.exists():
        print(f"[ERROR] {SRC} не найден. Запускай из корня проекта.")
        sys.exit(1)

    # Бэкап оригиналов
    shutil.copy(SRC,  SRC.with_suffix(".py.win_backup"))
    print(f"[OK] Бэкап: {SRC.with_suffix('.py.win_backup')}")

    text = SRC.read_text(encoding="utf-8")
    patched = patch_main(text)
    SRC.write_text(patched, encoding="utf-8")
    print(f"[OK] Пропатчен: {SRC}")

    if HELP.exists():
        shutil.copy(HELP, HELP.with_suffix(".py.win_backup"))
        h_text = HELP.read_text(encoding="utf-8")
        HELP.write_text(patch_helpers(h_text), encoding="utf-8")
        print(f"[OK] Пропатчен: {HELP}")
    else:
        print(f"[WARN] {HELP} не найден, пропущено.")

    print("\n Патч применён. Теперь выполни:")
    print("   pip install -r requirements_linux.txt")
    print("   sudo python WifiSecuritySystem.py")


if __name__ == "__main__":
    main()
