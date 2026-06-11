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
    """Show a native notification on Linux/Windows or fallback to messagebox/print."""
    try:
        if sys.platform.startswith("linux"):
            urgency = "critical" if severity == "CRITICAL" else "normal"
            try:
                subprocess.Popen(
                    ["notify-send", "-u", urgency, title, message],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except FileNotFoundError:
                pass
            except Exception:
                pass
        if sys.platform == "win32":
            try:
                messagebox.showinfo(title, message)
                return
            except Exception:
                pass
        try:
            messagebox.showinfo(title, message)
        except Exception:
            print(f"{title}: {message}")
    except Exception:
        try:
            print(f"{title}: {message}")
        except Exception:
            pass
