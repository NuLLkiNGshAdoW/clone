import threading
import sys
from tkinter import messagebox


def safe_len(x):
    try:
        return len(x)
    except Exception:
        return 0


# Initialize optional Windows notifier. If a richer implementation is
# available in the environment, replace this placeholder with it.
WinNotifier = None
if sys.platform == "win32":
    try:
        import ctypes  # noqa: F401

        class _WinNotifier:
            @staticmethod
            def send(title, message, severity="INFO"):
                # Placeholder: show a simple messagebox as a fallback
                try:
                    messagebox.showinfo(title, message)
                except Exception:
                    print(f"{title}: {message}")

        WinNotifier = _WinNotifier
    except Exception:
        WinNotifier = None


def show_system_toast(title: str, message: str, severity: str = "INFO"):
    """Show a native toast on Windows or fallback to messagebox/print.

    Attempts to use a platform notifier when available. Falls back to
    tkinter.messagebox and finally to printing to stdout.
    """
    try:
        if WinNotifier is not None and sys.platform == "win32":
            WinNotifier.send(title, message, severity)
        else:
            try:
                messagebox.showinfo(title, message)
            except Exception:
                print(f"{title}: {message}")
    except Exception:
        try:
            print(f"{title}: {message}")
        except Exception:
            pass
