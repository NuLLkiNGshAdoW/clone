import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

import sys as _sys
if _sys.platform == "win32":
    matplotlib.rcParams["font.family"] = ["Segoe UI", "Segoe UI Emoji", "DejaVu Sans"]
    FONT_FAMILY_SANS = "Segoe UI"
    FONT_FAMILY_SANS_BOLD = "Segoe UI Semibold"
    FONT_FAMILY_MONO = "Consolas"
else:
    matplotlib.rcParams["font.family"] = ["DejaVu Sans"]
    FONT_FAMILY_SANS = "DejaVu Sans"
    FONT_FAMILY_SANS_BOLD = "DejaVu Sans"
    FONT_FAMILY_MONO = "DejaVu Sans Mono"

import logging as _mpl_log
_mpl_log.getLogger("matplotlib.font_manager").setLevel(_mpl_log.ERROR)

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import gc, csv
import logging
import warnings
warnings.filterwarnings(
    "ignore",
    message=r"Glyph \d+.*missing from font",
    category=UserWarning,
)
import psutil, threading, time, json, os, sys, socket
import collections, random, queue, hashlib
import urllib.request, urllib.error, re
from utils.helpers import show_system_toast
from core.database import get_db
from core.topology import draw_topology
from core.i18n_manager import i18n, tr, TRANSLATIONS
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
import subprocess, ctypes
from core.whitelist import is_whitelisted, get_whitelist, add_whitelist_entry, remove_whitelist_entry

def _try_import_scapy():
    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        import scapy.all as _s
        return True
    except Exception:
        pass
    import os
    _script_dir = Path(__file__).resolve().parent
    _candidates = []
    for _venv_name in ("env1", "env", "venv", ".venv"):
        for _py_ver in ("Python313", "Python312", "Python311", "Python310", "Python39"):
            _candidates.append(_script_dir / _venv_name / "Lib" / "site-packages")
        _candidates.append(_script_dir / _venv_name / "lib" / "site-packages")
    for _sp in _candidates:
        if _sp.exists() and str(_sp) not in sys.path:
            sys.path.insert(0, str(_sp))
    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        import scapy.all as _s
        return True
    except Exception:
        pass
    return False

SCAPY_AVAILABLE = _try_import_scapy()
if SCAPY_AVAILABLE:
    import scapy.all as scapy

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("[WARNING] Flask not installed. Run: pip install flask flask-cors")

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

DEVICE_MAP = {
    "192.168.0.107": "Workstation (Almaty)",
    "192.168.0.1":   "Home Router / Gateway",
    "192.168.0.100": "Phone (Almaty)",
    "192.168.0.2":   "Desktop PC",
}

LOC_MAP = {
    "2.132.":   "Kazakhtelecom (Almaty)",
    "77.94.":   "Kazakhtelecom",
    "217.74.":  "Kazakhtelecom",
    "178.89.":  "Beeline KZ",
    "92.46.":   "Beeline KZ",
    "95.56.":   "Beeline KZ",
    "91.185.":  "Tele2 / Altel KZ",
    "94.247.":  "Tele2 / Altel KZ",
    "192.168.": "Local Network",
    "10.0.":    "Local Network",
    "172.16.":  "Local Network",
}

PORT_SERVICE_MAP = {
    80:   "HTTP",
    443:  "HTTPS",
    53:   "DNS",
    22:   "SSH",
    21:   "FTP",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    3389: "RDP",
    5353: "mDNS",
    1935: "RTMP (Stream)",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
}

APP_MAP = {
    "youtube":      "YouTube Video",
    "googlevideo":  "YouTube Video",
    "ytimg":        "YouTube Video",
    "instagram":    "Instagram",
    "tiktok":       "TikTok",
    "whatsapp":     "WhatsApp",
    "kaspi":        "Kaspi Pay",
    "halyk":        "Halyk Bank",
    "telegram":     "Telegram",
    "cloudflare":   "Cloudflare CDN",
    "1.1.1.1":      "Cloudflare DNS",
    "8.8.8.8":      "Google DNS",
    "8.8.4.4":      "Google DNS",
    "google":       "Google",
}

def _resolve_service(ip: str, port: int = 0) -> str:
    if ip in DEVICE_MAP:
        return DEVICE_MAP[ip]
    for prefix, label in LOC_MAP.items():
        if ip.startswith(prefix):
            svc = PORT_SERVICE_MAP.get(port, "")
            return f"{label}  {svc}".strip() if svc else label
    svc = PORT_SERVICE_MAP.get(port, "")
    return svc if svc else ip

def _build_flask_app(engine_ref, app_ref=None) -> "Flask":
    from functools import wraps
    import secrets

    flask_app = Flask("SOCSentinel")
    CORS(flask_app, resources={r"/api/*": {"origins": "*"}})

    # API Key management
    def get_or_create_api_key():
        cfg = load_config()
        key = cfg.get("web_api_key", "")
        if not key:
            key = secrets.token_urlsafe(32)
            cfg["web_api_key"] = key
            save_config(cfg)
        return key

    # Authentication decorator
    def require_api_key(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = get_or_create_api_key()
            # Extract API key from header or query parameter
            auth_header = request.headers.get('Authorization')
            key_from_header = None
            if auth_header and auth_header.startswith('Bearer '):
                key_from_header = auth_header.split('Bearer ')[1]
            key_from_query = request.args.get('api_key')
            provided_key = key_from_header or key_from_query
            
            if provided_key != api_key:
                return jsonify({'error': 'Unauthorized - Invalid API key'}), 401
            return f(*args, **kwargs)
        return decorated_function

    @flask_app.before_request
    def _count_request():
        if app_ref and app_ref():
            app = app_ref()
            app._flask_request_count += 1
            if load_config().get("web_log_requests"):
                logging.info(f"[Web] Request: {request.method} {request.path}")

    @flask_app.after_request
    def _cors_headers(response):
        response.headers["Access-Control-Allow-Origin"]  = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, ngrok-skip-browser-warning"
        )
        return response

    _api_stats_cache: list = [None]

    @flask_app.route("/api/stats")
    @require_api_key
    def api_stats():
        engine = engine_ref()
        if engine is None:
            return jsonify({"error": "Engine not available"}), 503

        acquired = engine.lock.acquire(timeout=0.05)
        if acquired:
            try:
                total        = engine.packet_stats.get("total", 0)
                bytes_       = engine.packet_stats.get("bytes", 0)
                protos       = dict(engine.proto_counts)
                blocked      = list(engine.blocked_ips)
                alerts_copy  = list(engine.alerts[-200:])
            finally:
                engine.lock.release()
            _api_stats_cache[0] = (total, bytes_, protos, blocked, alerts_copy)
        else:
            cached = _api_stats_cache[0]
            if cached is None:
                return jsonify({"error": "Engine busy, no cache yet"}), 503
            total, bytes_, protos, blocked, alerts_copy = cached
        alerts = alerts_copy[-50:]
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in alerts:
            sev = a.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        actor_counts: dict = {}
        for a in alerts_copy:
            actor = a.get("actor", "")
            if actor:
                actor_counts[actor] = actor_counts.get(actor, 0) + 1
        top_nodes = [
            {"ip": ip, "label": _resolve_service(ip), "count": cnt}
            for ip, cnt in sorted(actor_counts.items(),
                                  key=lambda x: x[1], reverse=True)[:5]
        ]
        recent_alerts = []
        for a in reversed(alerts[-10:]):
            recent_alerts.append({
                "time":       a.get("time", ""),
                "type":       a.get("type", ""),
                "actor":      a.get("actor", ""),
                "actor_name": _resolve_service(a.get("actor", "")),
                "severity":   a.get("severity", ""),
            })
        alerts_normalized = [
            {
                "time":     a["time"],
                "type":     a["type"],
                "src":      a["actor"],
                "src_name": a["actor_name"],
                "severity": a["severity"].lower(),
            }
            for a in recent_alerts
        ]
        return jsonify({
            "packets":          total,
            "bytes":            bytes_,
            "bytes_mb":         round(bytes_ / (1024 * 1024), 2),
            "protocols":        protos,
            "blocked_ips":      blocked,
            "blocked_count":    len(blocked),
            "status":           "live",
            "threats":          sev_counts,
            "threats_critical": sev_counts.get("CRITICAL", 0),
            "threats_high":     sev_counts.get("HIGH",     0),
            "threats_medium":   sev_counts.get("MEDIUM",   0),
            "threats_low":      sev_counts.get("LOW",      0),
            "alerts":           alerts_normalized,
            "recent_alerts":    recent_alerts,
            "top_nodes":        top_nodes,
        })

    @flask_app.route("/api/health")
    @require_api_key
    def api_health():
        return jsonify({"ok": True, "service": "SOC Sentinel"})

    @flask_app.route("/")
    def mobile_dashboard():
        html_path = Path(__file__).resolve().parent / "web" / "dashboard.html"
        if html_path.exists():
            return html_path.read_text(encoding="utf-8")
        return "<h1>SOC Sentinel</h1>", 404

    @flask_app.route("/api/network")
    def api_network():
        from utils.network import get_connection_urls, get_primary_lan_ip
        port = int(load_config().get("web_port", 5000))
        urls = get_connection_urls(port)
        primary = get_primary_lan_ip()
        api_key = get_or_create_api_key()
        # Include API key in URLs for convenience
        urls_with_key = []
        for url in urls:
            if "?" in url:
                urls_with_key.append(f"{url}&api_key={api_key}")
            else:
                urls_with_key.append(f"{url}?api_key={api_key}")
        primary_url = f"http://{primary}:{port}?api_key={api_key}" if primary else None
        return jsonify({"port": port, "hostname": socket.gethostname(),
            "primary_ip": primary, "primary_url": primary_url,
            "urls": urls_with_key, "api_key": api_key, "same_network_required": True})

    @flask_app.route("/api/whitelist", methods=["GET"])
    @require_api_key
    def api_whitelist_get():
        return jsonify(get_whitelist())

    @flask_app.route("/api/whitelist", methods=["POST"])
    @require_api_key
    def api_whitelist_add():
        req = request.get_json(silent=True) or {}
        ident = (req.get("id") or req.get("identifier") or "").strip()
        name = (req.get("name") or "").strip()
        if not ident:
            return jsonify({"error": "missing id"}), 400
        data = add_whitelist_entry(ident, name)
        return jsonify(data)

    @flask_app.route("/api/whitelist/<ident>", methods=["DELETE"])
    @require_api_key
    def api_whitelist_remove(ident):
        data = remove_whitelist_entry(ident)
        return jsonify(data)
        
    @flask_app.route("/api/block/<ip>", methods=["POST"])
    @require_api_key
    def api_block_ip(ip):
        engine = engine_ref()
        if engine:
            engine.block_ip(ip)
            return jsonify({"ok": True, "ip": ip})
        return jsonify({"error": "Engine not available"}), 503
        
    @flask_app.route("/api/block/<ip>", methods=["DELETE"])
    @require_api_key
    def api_unblock_ip(ip):
        engine = engine_ref()
        if engine:
            engine.unblock_ip(ip)
            return jsonify({"ok": True, "ip": ip})
        return jsonify({"error": "Engine not available"}), 503
        
    @flask_app.route("/api/alerts", methods=["GET"])
    @require_api_key
    def api_alerts():
        engine = engine_ref()
        if engine:
            with engine.lock:
                alerts = list(engine.alerts[-200:])
            return jsonify(alerts)
        return jsonify({"error": "Engine not available"}), 503

    return flask_app

ROOT_DIR    = Path(__file__).resolve().parent
CONFIG_FILE = ROOT_DIR / "sentinel_config.json"
USERS_FILE  = ROOT_DIR / "sentinel_users.json"
LOG_DIR     = ROOT_DIR / "sentinel_logs"
LOG_DIR.mkdir(exist_ok=True)

DEFAULT_CONFIG = {
    "adapter": "", "theme": "dark", "accent": "cyan",
    "max_table_rows": 200, "alert_sound": False,
    "auto_block": False, "auto_block_firewall": False,
    "auto_block_thresh": 5, "log_to_file": True,
    "data_exfil_kb": 8, "syn_thresh": 100,
    "scan_thresh": 15, "icmp_thresh": 50,
    "ai_api_key": "", "gemini_api_key": "", "openai_api_key": "",
    "demo_mode": False,
    "pps_thresh": 200,
    "ai_provider": "Claude",
    "ai_auto_fallback": True,
    "ai_log_dialogs": True,
    "language": "en",
    "deep_http_capture": False,
    "web_port": 5000,
    "web_enabled": True,
    "web_firewall": True,
    "web_autostart": False,
    "web_log_requests": False,
    "device_fingerprint_enabled": True,
    "behavior_score_threshold": 70,
    "web_api_key": "",
    "encrypt_config": True,
    # New features
    "email_server": "smtp.gmail.com",
    "email_port": "587",
    "email_user": "",
    "email_password": "",
    "email_recipient": "",
    "discord_webhook": "",
    "slack_webhook": "",
    "system_toasts": False,
    "virustotal_api": "",
    "abuseipdb_api": "",
    "auto_backup": False,
    "backup_interval": "24",
}

from utils.auth import (
    load_users as _auth_load_users, save_users as _auth_save_users,
    authenticate, register_user, upgrade_password_on_login, can as rbac_can,
)
from utils.encryption import (
    get_or_create_key, encrypt_config_values, decrypt_config_values
)
from utils.crypto import load_json_encrypted, encrypt_json

def load_users():
    return _auth_load_users()

def save_users(u):
    _auth_save_users(u)

_ENCRYPTION_KEY = None

def _get_key():
    global _ENCRYPTION_KEY
    if _ENCRYPTION_KEY is None:
        _ENCRYPTION_KEY = get_or_create_key()
    return _ENCRYPTION_KEY

def load_config():
    global _ENCRYPTION_KEY
    config_enc_path = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".enc")
    cfg = None

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = None

    if cfg is None and config_enc_path.exists():
        try:
            cfg = load_json_encrypted(CONFIG_FILE, DEFAULT_CONFIG)
        except Exception:
            logging.exception("Error loading encrypted config file")
            cfg = None

    if cfg is None:
        cfg = dict(DEFAULT_CONFIG)

    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)

    try:
        cfg = decrypt_config_values(cfg, _get_key())
    except Exception:
        logging.exception("Error decrypting config values")

    # Auto-detect WiFi interface on Linux/Kali
    if sys.platform.startswith('linux') and cfg.get('adapter') == 'Беспроводная сеть':
        cfg['adapter'] = 'wlan0'
        logging.info("[Config] Auto-detected WiFi interface on Linux: wlan0")

    return cfg


def save_config(cfg):
    cfg_to_save = dict(cfg)
    config_enc_path = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".enc")
    try:
        if cfg_to_save.get("encrypt_config"):
            cfg_to_save = encrypt_config_values(cfg_to_save, _get_key())
        else:
            cfg_to_save = decrypt_config_values(cfg_to_save, _get_key())
    except Exception:
        logging.exception("Failed to prepare config values for saving")

    try:
        if cfg_to_save.get("encrypt_config"):
            if encrypt_json(CONFIG_FILE, cfg_to_save):
                return
        else:
            if config_enc_path.exists():
                try:
                    config_enc_path.unlink()
                except Exception:
                    pass
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg_to_save, f, indent=2)
    except Exception:
        logging.exception("Failed to save config file")

CFG   = load_config()
USERS = load_users()

ACCENT_MAP = {"cyan": "#00D4FF", "green": "#00FF88",
              "orange": "#FF8C42", "purple": "#BD00FF"}

def build_theme(theme="dark", accent_name="cyan"):
    accent = ACCENT_MAP.get(accent_name, "#00D4FF")
    if theme == "dark":
        return {
            "bg_deep": "#050810", "bg_panel": "#0A0F1E", "bg_card": "#0D1528",
            "bg_hover": "#152040", "text_primary": "#E8F4FD", "text_dim": "#4A6FA5",
            "text_muted": "#2A3F5F", "border": "#1A2A4A", "accent": accent,
            "safe": "#00FF88", "warn": "#FFD60A", "danger": "#FF3B5C",
            "info": "#00D4FF", "accent_purple": "#BD00FF", "accent_orange": "#FF8C42",
            "accent_yellow": "#FFD60A", "mpl_bg": "#0A0F1E",
        }
    else:
        return {
            "bg_deep": "#F0F4F8", "bg_panel": "#FFFFFF", "bg_card": "#EEF2F7",
            "bg_hover": "#DCE8F5", "text_primary": "#1A2A4A", "text_dim": "#5A7A9A",
            "text_muted": "#8AAABB", "border": "#C8D8E8", "accent": accent,
            "safe": "#00AA55", "warn": "#CC8800", "danger": "#DD2244",
            "info": "#0088CC", "accent_purple": "#8800CC", "accent_orange": "#CC5500",
            "accent_yellow": "#AA7700", "mpl_bg": "#FFFFFF",
        }

T = build_theme(CFG["theme"], CFG["accent"])
DEFAULT_CORNER = 12

FONT_HEADER = (FONT_FAMILY_SANS_BOLD, 13)
FONT_BODY   = (FONT_FAMILY_SANS, 11)
FONT_MONO   = (FONT_FAMILY_MONO, 10)
FONT_SMALL  = (FONT_FAMILY_SANS, 9)
FONT_TINY   = (FONT_FAMILY_SANS, 8)

def _adjust_color(hexcol: str, factor: float) -> str:
    hexcol = hexcol.lstrip('#')
    if len(hexcol) != 6: return hexcol
    try:
        r = int(hexcol[0:2], 16); g = int(hexcol[2:4], 16); b = int(hexcol[4:6], 16)
        r = max(0, min(255, int(r * factor)))
        g = max(0, min(255, int(g * factor)))
        b = max(0, min(255, int(b * factor)))
        return f"#{r:02X}{g:02X}{b:02X}"
    except Exception:
        return "#FFFFFF"

def smooth_list(data: list, window: int = 3) -> list:
    if window <= 1 or not data:
        return list(data)
    out = []
    n = len(data)
    half = window // 2
    for i in range(n):
        s = 0.0; cnt = 0
        for j in range(i - half, i + half + 1):
            if 0 <= j < n:
                s += data[j]; cnt += 1
        out.append(s / max(1, cnt))
    return out

def get_signatures():
    return {
        "PORT_SCAN":   {"thresh": CFG["scan_thresh"],        "window": 5,  "sev": "HIGH"},
        "SYN_FLOOD":   {"thresh": CFG["syn_thresh"],         "window": 2,  "sev": "CRITICAL"},
        "ARP_SPOOF":   {"thresh": 3,                         "window": 3,  "sev": "CRITICAL"},
        "DNS_TUNNEL":  {"thresh": 5,                         "window": 10, "sev": "HIGH"},
        "ICMP_FLOOD":  {"thresh": CFG["icmp_thresh"],        "window": 2,  "sev": "MEDIUM"},
        "BRUTE_FORCE": {"thresh": 8,                         "window": 30, "sev": "HIGH"},
        "DATA_EXFIL":  {"thresh": CFG["data_exfil_kb"]*1024, "window": 1,  "sev": "CRITICAL"},
    }

def set_dpi_awareness():
    # Linux/macOS: no special DPI setup required here.
    return

def ttk_style():
    s = ttk.Style(); s.theme_use("default")
    for name in ("Sentinel.Treeview", "Alert.Treeview"):
        s.configure(name, background=T["bg_panel"], foreground=T["text_primary"],
            rowheight=24, fieldbackground=T["bg_panel"], borderwidth=0, font=FONT_MONO)
        s.configure(f"{name}.Heading", background=T["bg_card"], foreground=T["accent"],
            font=(FONT_FAMILY_SANS_BOLD, 10, "bold"), relief="flat")
        s.map(name, background=[("selected", T["bg_hover"])],
              foreground=[("selected", T["accent"])])

def _toast_async(title: str, msg: str) -> None:
    threading.Thread(
        target=show_system_toast,
        args=(title, msg),
        daemon=True,
        name="ToastThread",
    ).start()

class ThreatDetector:

    @staticmethod
    def detect(engine) -> list[str]:
        alerts = []
        if not engine.lock.acquire(timeout=0.05):
            return ["Stats temporarily unavailable"]
        try:
            syn    = engine.proto_counts.get("TCP", 0)
            icmp   = engine.proto_counts.get("ICMP", 0)
            dns    = engine.proto_counts.get("DNS", 0)
            total  = engine.packet_stats.get("total", 0)
            bytes_ = engine.packet_stats.get("bytes", 0)
            blocked = len(engine.blocked_ips)
            now = datetime.now()
            recent = []
            for a in engine.alerts[-200:]:
                try:
                    at = datetime.strptime(a["time"], "%H:%M:%S").replace(
                        year=now.year, month=now.month, day=now.day)
                    if (now - at).total_seconds() < 60:
                        recent.append(a)
                except Exception: pass
        finally:
            engine.lock.release()
        crit = sum(1 for a in recent if a.get("severity") == "critical")
        high = sum(1 for a in recent if a.get("severity") == "high")
        if crit > 0:
            alerts.append(f"{crit} critical threats in last 60s")
        if high > 0:
            alerts.append(f"{high} high severity alerts in last 60s")
        if icmp > CFG.get("icmp_thresh", 50) * 2:
            alerts.append(f"High ICMP traffic ({icmp} pkts)")
        if dns > 500:
            alerts.append(f"Elevated DNS queries ({dns})")
        if blocked > 0:
            alerts.append(f"{blocked} IPs currently blocked")
        if bytes_ > 50 * 1024 * 1024:
            mb = bytes_ / (1024 * 1024)
            alerts.append(f"High data volume: {mb:.1f} MB")
        if not alerts:
            alerts.append("No active threats detected")
        return alerts

try:
    from core.threat_engine import ThreatEngine
except Exception:
    class ThreatEngine:
        def __init__(self, bot=None):
            self.bot = bot
            self.result_q = queue.Queue(maxsize=4000)
            self.alerts = []
            self.alert_callbacks = []
            self.blocked_ips = set()
            self.packet_stats = collections.defaultdict(int)
            self.proto_counts = collections.defaultdict(int)
            self.app_counts = collections.defaultdict(int)
            self.lock = threading.Lock()
        def submit(self, pkt): pass
        def reset_stats(self): pass
        def set_demo_mode(self, v): pass
        def reload_sigs(self): pass
        def shutdown(self): pass

class KPICard(ctk.CTkFrame):
    def __init__(self, master, title, value="0", color=None, icon="", subtitle="", **kw):
        color = color or T["accent"]
        self._current_color = color
        super().__init__(master, fg_color=T["bg_card"], corner_radius=DEFAULT_CORNER,
                         border_width=1, border_color=T["border"], **kw)
        self._color_bar = ctk.CTkFrame(self, fg_color=color, height=3, corner_radius=0)
        self._color_bar.pack(fill="x")
        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=12)
        top = ctk.CTkFrame(inner, fg_color="transparent"); top.pack(fill="x")
        self._icon_label = ctk.CTkLabel(top, text=icon, font=(FONT_FAMILY_MONO,20), text_color=color)
        self._icon_label.pack(side="left")
        self._title_raw = title
        self._title_label = ctk.CTkLabel(top, text=f"  {title}", font=FONT_TINY,
                                         text_color=T["text_dim"])
        self._title_label.pack(side="left")
        self._val = ctk.CTkLabel(inner, text=str(value),
                                  font=(FONT_FAMILY_MONO,30,"bold"), text_color=color)
        self._val.pack(anchor="w", pady=(4,0))
        if subtitle:
            self._sub_raw = subtitle
            self._sub = ctk.CTkLabel(inner, text=subtitle, font=FONT_TINY,
                                      text_color=T["text_muted"])
            self._sub.pack(anchor="w")
        else: self._sub = None

        def _on_enter(e=None):
            try: self.configure(border_color=T["accent"], border_width=2,
                                 fg_color=T["bg_hover"])
            except Exception: pass
        def _on_leave(e=None):
            try: self.configure(border_color=T["border"], border_width=1,
                                 fg_color=T["bg_card"])
            except Exception: pass
        self.bind("<Enter>", _on_enter); self.bind("<Leave>", _on_leave)
        try:
            i18n.register(self.refresh_ui)
            self.bind("<Destroy>", lambda e: i18n.unregister(self.refresh_ui))
        except Exception: pass

    def set(self, v, subtitle=None):
        self._val.configure(text=str(v))
        if subtitle and self._sub: self._sub.configure(text=str(subtitle))

    def set_color(self, color):
        self._current_color = color
        self._color_bar.configure(fg_color=color)
        self._val.configure(text_color=color)
        self._icon_label.configure(text_color=color)

    def refresh_ui(self):
        try:
            key = self._title_raw.lower().strip().replace(" ", "_").replace("%","pct")
            new_title = TRANSLATIONS.get(CFG.get("language","en"), {}).get(key)
            if new_title:
                self._title_label.configure(text=f"  {new_title}")
            else:
                self._title_label.configure(text=f"  {self._title_raw}")
            if getattr(self, '_sub_raw', None) and self._sub:
                skey = self._sub_raw.lower().strip().replace(" ", "_")
                new_sub = TRANSLATIONS.get(CFG.get("language","en"), {}).get(skey)
                if new_sub:
                    self._sub.configure(text=new_sub)
                else:
                    self._sub.configure(text=self._sub_raw)
        except Exception as e:
            # Suppress TclError when widget is destroyed during UI rebuild
            try:
                if isinstance(e, tk.TclError):
                    return
            except Exception:
                pass
            logging.exception("KPICard refresh_ui failed")

def section_label(parent, text, sub=""):
    f = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=DEFAULT_CORNER)
    f.pack(fill="x", padx=18, pady=(14,4))
    ctk.CTkLabel(f, text=text, font=FONT_HEADER, text_color=T["accent"]).pack(side="left")
    if sub:
        ctk.CTkLabel(f, text=f"    {sub}", font=FONT_SMALL,
                     text_color=T["text_dim"]).pack(side="left")
    ctk.CTkFrame(parent, fg_color=T["border"], height=1).pack(fill="x", padx=18, pady=(0,8))
    return f

def make_canvas(parent, fig):
    c = FigureCanvasTkAgg(fig, master=parent)
    w = c.get_tk_widget()
    try: w.configure(bg=T.get("mpl_bg","#000000"))
    except Exception: pass
    w.pack(fill="both", expand=True, padx=6, pady=6)
    try:
        tb = ctk.CTkFrame(parent, fg_color=T["bg_card"], corner_radius=DEFAULT_CORNER,
                          border_width=1, border_color=T["border"])
        tb.pack(fill="x", padx=6, pady=(0,6))
        def _save():
            path = filedialog.asksaveasfilename(defaultextension='.png',
                                                filetypes=[('PNG','*.png')])
            if path: fig.savefig(path, dpi=200)
        ctk.CTkButton(tb, text='', width=36, height=26,
                      fg_color=_adjust_color(T['accent'], 0.95), hover_color=_adjust_color(T['accent'],1.25),
                      corner_radius=DEFAULT_CORNER, command=_save).pack(side='right', padx=4, pady=4)
    except Exception: pass
    return c

class AuthWindow(ctk.CTkToplevel):
    def __init__(self, master=None):
        logging.info("[AuthWindow] __init__ started")
        super().__init__(master)
        logging.info("[AuthWindow] CTkToplevel.__init__() completed")
        self.title("SOC SENTINEL  Authentication")
        self.geometry("460x560"); self.resizable(False, False)
        self.configure(fg_color=T["bg_deep"]); self.grab_set()
        self.result = None; self._mode = tk.StringVar(value="login")
        logging.info("[AuthWindow] Building form")
        self._build()
        logging.info("[AuthWindow] Form built, setting protocol")
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        try:
            i18n.register(self.refresh_ui)
            self.bind("<Destroy>", lambda e: i18n.unregister(self.refresh_ui))
        except Exception: pass
        logging.info("[AuthWindow] Updating idletasks and positioning window")
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - 460) // 2
        y = (self.winfo_screenheight() - 560) // 2
        self.geometry(f"460x560+{x}+{y}")
        logging.info("[AuthWindow] __init__ completed")

    def _build(self):
        logging.info("[AuthWindow._build] started")
        hdr = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=DEFAULT_CORNER, height=90, border_width=1, border_color=T["border"])
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="", font=(FONT_FAMILY_SANS_BOLD,38),
                     text_color=T["accent"]).pack(pady=(10,0))
        ctk.CTkLabel(hdr, text="SOC SENTINEL", font=(FONT_FAMILY_SANS_BOLD,13),
                     text_color=T["text_primary"]).pack()
        tab = ctk.CTkFrame(self, fg_color=T["bg_card"], corner_radius=10)
        tab.pack(padx=30, pady=(20,0), fill="x")
        self._mode_rbs = {}
        for val, icon_key in [("login","sign_in"),("register","register")]:
            lbl = ("  " if val=="login" else "  ") + tr(icon_key)
            rb = ctk.CTkRadioButton(tab, text=lbl, variable=self._mode, value=val,
                               font=FONT_SMALL, text_color=T["text_primary"],
                               fg_color=T["accent"], command=self._refresh_mode)
            rb.pack(side="left", expand=True, padx=10, pady=8)
            self._mode_rbs[val] = (rb, icon_key)
        self._form = ctk.CTkFrame(self, fg_color="transparent", corner_radius=DEFAULT_CORNER)
        self._form.pack(padx=30, pady=10, fill="x")
        self._build_form()
        self._status = ctk.CTkLabel(self, text="", font=FONT_SMALL, text_color=T["danger"])
        self._status.pack(pady=(0,8))
        self._submit_btn = ctk.CTkButton(self, text=tr("sign_in"), height=44,
                                          font=FONT_HEADER, fg_color=_adjust_color(T["accent"],0.95),
                                          hover_color=_adjust_color(T["accent"],1.25),
                                          corner_radius=DEFAULT_CORNER, text_color=T["bg_deep"], command=self._submit)
        self._submit_btn.pack(padx=30, fill="x")
        logging.info("[AuthWindow._build] completed")

    def _build_form(self):
        for w in self._form.winfo_children(): w.destroy()
        mode = self._mode.get()
        def field(lbl_key, ph_key, show=""):
            ctk.CTkLabel(self._form, text=tr(lbl_key), font=FONT_SMALL,
                         text_color=T["text_dim"]).pack(anchor="w", pady=(8,2))
            e = ctk.CTkEntry(self._form, placeholder_text=tr(ph_key), show=show,
                             fg_color=T["bg_card"], border_color=T["border"],
                             text_color=T["text_primary"], font=FONT_BODY, height=38,
                             corner_radius=8)
            e.pack(fill="x"); return e
        self._user_ent = field("username", "username")
        self._pass_ent = field("password", "password", "•")
        self._pass2_ent = field("confirm_password", "confirm_password", "•") if mode == "register" else None
        self._role_var  = None

    def _refresh_mode(self):
        self._build_form()
        submit_text = tr('sign_in') if self._mode.get() == 'login' else tr('register')
        try: self._submit_btn.configure(text=submit_text)
        except Exception: pass

    def refresh_ui(self):
        try:
            for val, (rb, key) in getattr(self, '_mode_rbs', {}).items():
                icon = '  ' if val == 'login' else '  '
                rb.configure(text=icon + tr(key))
            self._build_form()
            submit_text = tr('sign_in') if self._mode.get() == 'login' else tr('register')
            try: self._submit_btn.configure(text=submit_text)
            except Exception: pass
            try: self._status.configure(text='')
            except Exception: pass
        except Exception as e:
            # Suppress TclError when widget is destroyed during UI rebuild
            if "_tkinter.TclError" not in str(type(e).__name__):
                logging.exception('AuthWindow refresh_ui failed')

    def _submit(self):
        mode = self._mode.get()
        username = self._user_ent.get().strip(); password = self._pass_ent.get()
        if not username or not password:
            self._status.configure(text=tr('fill_fields')); return
        if mode == "login":
            auth = authenticate(username, password, USERS)
            if not auth:
                self._status.configure(text=tr('invalid_credentials')); return
            upgrade_password_on_login(username, password, USERS)
            self.result = auth; self.destroy()
        else:
            if username in USERS:
                self._status.configure(text=tr('username_taken')); return
            pw2 = self._pass2_ent.get() if self._pass2_ent else ""
            if password != pw2:
                self._status.configure(text=tr('pw_mismatch')); return
            if len(password) < 6:
                self._status.configure(text=tr('pw_minlen')); return
            if not register_user(username, password, USERS, role="operator"):
                self._status.configure(text=tr('username_taken')); return
            self.result = (username, "operator"); self.destroy()

    def _cancel(self): self.result = None; self.destroy()

class AIAssistantPanel(ctk.CTkFrame):
    PROVIDERS = {
        "Claude": {"color": "#00D4FF", "icon": "", "model": "claude-sonnet-4-20250514",
                   "cfg_key": "ai_api_key"},
        "Gemini": {"color": "#00FF88", "icon": "", "model": "gemini-2.5-flash",
                   "cfg_key": "gemini_api_key"},
        "OpenAI": {"color": "#BD00FF", "icon": "", "model": "gpt-4o-mini",
                   "cfg_key": "openai_api_key"},
    }
    INTENTS = {
        "analyze":  ["analyze","analysis","check","inspect","review","examine"],
        "status":   ["status","summary","overview","how many","what is","show me"],
        "block":    ["block","ban","stop","blacklist","kill","drop"],
        "explain":  ["explain","what is","how does","why","define","meaning"],
        "threats":  ["threat","attack","danger","critical","flood","scan","brute"],
    }

    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color=T["bg_panel"], corner_radius=DEFAULT_CORNER,
                         border_width=1, border_color=T["border"], **kw)
        self.engine    = engine
        self._history  = []
        self._thinking = False
        self._provider = tk.StringVar(value=CFG.get("ai_provider","Claude"))
        self._stream_after = None
        self._log_path = LOG_DIR / f"ai_dialogs_{datetime.now().strftime('%Y%m%d')}.log"
        self._build()

    def _build(self):
        hdr = ctk.CTkFrame(self, fg_color=T["bg_card"], corner_radius=DEFAULT_CORNER, height=50, border_width=1, border_color=T["border"])
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=tr("ai_soc_analyst"), font=FONT_HEADER,
                     text_color=T["accent"]).pack(side="left", padx=16, pady=12)
        self._prov_badge = ctk.CTkLabel(hdr, text="", font=FONT_TINY,
                                         text_color=T["bg_deep"], fg_color=T["accent"],
                                         corner_radius=6, width=80, height=20)
        self._prov_badge.pack(side="right", padx=10)
        self._update_badge()

        prov_frame = ctk.CTkFrame(self, fg_color=T["bg_card"], corner_radius=DEFAULT_CORNER, border_width=1, border_color=T["border"])
        prov_frame.pack(fill="x")
        self._prov_btns = {}
        for name, info in self.PROVIDERS.items():
            active = (name == self._provider.get())
            btn = ctk.CTkButton(
                prov_frame, text=f"{info['icon']} {name}", width=0, height=36,
                font=FONT_SMALL,
                fg_color=_adjust_color(info["color"] if active else T["bg_card"], 0.98) if active else T["bg_card"],
                text_color=T["bg_deep"] if active else T["text_dim"],
                hover_color=_adjust_color(info.get("color", T["accent"]), 1.12), corner_radius=DEFAULT_CORNER,
                command=lambda n=name: self._switch_provider(n))
            btn.pack(side="left", expand=True, fill="x", padx=3, pady=4)
            self._prov_btns[name] = btn

        self._key_frames = {}; self._key_entries = {}
        for name, info in self.PROVIDERS.items():
            f = ctk.CTkFrame(self, fg_color=T["bg_card"], corner_radius=DEFAULT_CORNER, border_width=1, border_color=T["border"])
            ctk.CTkLabel(f, text=f"{name} Key:", font=FONT_TINY,
                         text_color=T["text_dim"]).pack(side="left", padx=(12,4), pady=6)
            ph_map = {"Claude":"sk-ant-","Gemini":"AIza","OpenAI":"sk-"}
            ent = ctk.CTkEntry(f, show="", width=140, placeholder_text=ph_map[name],
                               fg_color=T["bg_deep"], border_color=T["border"],
                               text_color=T["text_primary"], font=FONT_TINY, corner_radius=8)
            if CFG.get(info["cfg_key"]): ent.insert(0, CFG[info["cfg_key"]])
            ent.pack(side="left", padx=4, pady=6)
            ctk.CTkButton(f, text=tr("save"), width=46, height=24, font=FONT_TINY,
                          fg_color=T["accent"], text_color=T["bg_deep"],
                          command=lambda n=name, k=info["cfg_key"], e=ent:
                              self._save_key(n, k, e)).pack(side="left", padx=4)
            self._key_frames[name] = f; self._key_entries[name] = ent
        self._key_frames[self._provider.get()].pack(fill="x")

        cur = self._provider.get()
        self._model_lbl = ctk.CTkLabel(self, font=FONT_TINY, text_color=T["text_muted"],
                                        text=f"Model: {self.PROVIDERS[cur]['model']}")
        self._model_lbl.pack(anchor="w", padx=14, pady=(2,0))

        self.chat_box = ctk.CTkTextbox(self, fg_color=T["bg_deep"],
                                        text_color=T["text_primary"],
                                        font=FONT_BODY, wrap="word",
                                        activate_scrollbars=True)
        try: self.chat_box.tag_configure("ai", spacing3=6)
        except Exception: pass
        self.chat_box.pack(fill="both", expand=True, padx=6, pady=6)
        self.chat_box.configure(state="disabled")
        try:
            self.chat_box.tag_config("user", foreground=T["accent"], font=FONT_BODY)
            self.chat_box.tag_config("ai", foreground=T["safe"], font=FONT_BODY)
            self.chat_box.tag_config("sys", foreground=T["warn"], font=FONT_BODY)
        except Exception: pass

        self._chips_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._chips_frame.pack(fill="x", padx=6, pady=(0,4))
        self._render_chips()

        inp = ctk.CTkFrame(self, fg_color=T["bg_card"], corner_radius=DEFAULT_CORNER, border_width=1, border_color=T["border"])
        inp.pack(fill="x", padx=6, pady=(0,8))
        self._inp = ctk.CTkEntry(inp, placeholder_text=tr("ask_anything"),
                                  fg_color=T["bg_deep"], border_color=T["border"],
                                  text_color=T["text_primary"], font=FONT_BODY, corner_radius=8)
        self._inp.pack(side="left", fill="x", expand=True, padx=(8,6), pady=8)
        self._inp.bind("<Return>", lambda e: self._send())
        ctk.CTkButton(inp, text=tr("send"), width=40, height=36,
                      fg_color=_adjust_color(T["accent"],0.95), hover_color=_adjust_color(T["accent"],1.2),
                      text_color=T["bg_deep"], corner_radius=DEFAULT_CORNER,
                      font=(FONT_FAMILY_SANS_BOLD,14), command=self._send
                      ).pack(side="right", padx=(0,8), pady=8)
        ctk.CTkButton(inp, text=tr("clear_chat"), width=36, height=36,
                      fg_color=T["bg_card"], hover_color=_adjust_color(T["bg_card"],1.05), text_color=T["text_dim"],
                      corner_radius=DEFAULT_CORNER, command=self._clear_chat).pack(side="right", padx=4, pady=8)

        self._append_msg("assistant", tr("ai_ready_message"))
        self._chips_tick()

    def _render_chips(self):
        for w in self._chips_frame.winfo_children(): w.destroy()
        chips = self._get_smart_chips()
        for chip_text, chip_prompt in chips:
            ctk.CTkButton(
                self._chips_frame, text=chip_text, width=0, height=24,
                font=FONT_TINY, fg_color=T["bg_card"], text_color=T["text_dim"],
                corner_radius=12, hover_color=T["bg_hover"],
                command=lambda p=chip_prompt: self._send(p)
            ).pack(side="left", padx=3, pady=2)

    def _get_smart_chips(self) -> list[tuple[str,str]]:
        chips = [("Network status", "Give me a brief network status summary"),
                 ("Analyze traffic",  "Analyze the current traffic patterns")]
        recent = [a for a in self.engine.alerts[-50:]
                  if a.get("severity") in ("critical","high")]
        if recent:
            top_actor = collections.Counter(a["actor"] for a in recent).most_common(1)
            if top_actor:
                ip = top_actor[0][0]
                chips.insert(0, (f"Block {ip}", f"Should I block IP {ip}? Explain the risk."))
            chips.insert(0, ("Explain threats", "Explain the current active threats in detail"))
        if self.engine.proto_counts.get("ICMP",0) > 100:
            chips.append(("ICMP spike", "Why is there so much ICMP traffic?"))
        if self.engine.proto_counts.get("DNS",0) > 300:
            chips.append(("DNS activity", "Is the DNS activity suspicious?"))
        if len(self.engine.blocked_ips) > 0:
            chips.append(("Blocked IPs", "List and explain the currently blocked IPs"))
        return chips[:5]

    def _chips_tick(self):
        try: self._render_chips()
        except Exception: pass
        self.after(10000, self._chips_tick)

    def _switch_provider(self, name):
        self._provider.set(name); CFG["ai_provider"] = name
        for n, btn in self._prov_btns.items():
            info = self.PROVIDERS[n]; active = (n == name)
            btn.configure(fg_color=info["color"] if active else T["bg_card"],
                          text_color=T["bg_deep"] if active else T["text_dim"])
        for n, f in self._key_frames.items(): f.pack_forget()
        self._key_frames[name].pack(fill="x")
        self._model_lbl.configure(text=f"Model: {self.PROVIDERS[name]['model']}")
        self._update_badge()
        self._append_msg("system", f"Switched to {name}")

    def _update_badge(self):
        name = self._provider.get()
        info = self.PROVIDERS.get(name, {})
        self._prov_badge.configure(text=f"  {info.get('icon','?')} {name}  ",
                                    fg_color=info.get("color", T["accent"]))

    def _save_key(self, provider_name, cfg_key, entry):
        key = entry.get().strip(); CFG[cfg_key] = key
        self._append_msg("system", f" {provider_name} API key saved.")

    def _build_prompt(self, user_text: str) -> str:
        snap    = self.engine.get_snapshot()
        threats = ThreatDetector.detect(self.engine)
        mode    = snap["mode"]
        intent  = self._detect_intent(user_text)
        intent_instructions = {
            "analyze":  "Perform a detailed security analysis of the data below. Identify anomalies, patterns, and risk factors.",
            "status":   "Provide a concise 3-5 sentence status report. Use bullet points.",
            "block":    "Provide a specific recommendation on whether to block the mentioned IP. Include risk assessment and steps.",
            "explain":  "Explain the concept clearly. Then relate it to the current data if relevant.",
            "threats":  "Focus on the active threats. Prioritise by severity. Give response steps.",
            "default":  "Answer the question using the network data provided.",
        }
        instruction = intent_instructions.get(intent, intent_instructions["default"])
        snap_text = json.dumps(snap, indent=2, default=str)
        prompt = f"""You are a SOC (Security Operations Center) AI analyst embedded in SOC Sentinel.

STRICT RULES  YOU MUST FOLLOW THESE:
1. Analyze ONLY the data provided in [NETWORK DATA] below.
2. DO NOT invent, guess, or assume any numbers not in the data.
3. If data is unavailable or zero  state that explicitly.
4. Be concise and actionable. Use security terminology.
5. If [{mode}] mode is SIMULATION, note that data is synthetic.

TASK: {instruction}

[AUTOMATED THREAT DETECTION]
{chr(10).join(threats)}

[NETWORK DATA]
{snap_text}

[USER QUESTION]
{user_text}"""
        return prompt

    def _detect_intent(self, text: str) -> str:
        text_lower = text.lower()
        for intent, keywords in self.INTENTS.items():
            if any(kw in text_lower for kw in keywords):
                return intent
        return "default"

    def _send(self, text=None):
        if self._thinking: return
        msg = text or self._inp.get().strip()
        if not msg: return
        self._inp.delete(0, "end")
        self._append_msg("user", msg)
        full_prompt = self._build_prompt(msg)
        api_messages = self._history[-18:] + [{"role":"user","content": full_prompt}]
        self._history.append({"role": "user", "content": msg})
        self._thinking = True
        self._append_msg("assistant", tr("analyzing"))
        threading.Thread(target=self._dispatch, args=(api_messages,), daemon=True).start()

    def _dispatch(self, api_messages):
        provider_order = [self._provider.get()]
        if CFG.get("ai_auto_fallback", True):
            for p in self.PROVIDERS:
                if p not in provider_order: provider_order.append(p)
        last_error = None
        for provider in provider_order:
            key = CFG.get(self.PROVIDERS[provider]["cfg_key"],"").strip()
            if not key: continue
            try:
                reply = self._call(provider, api_messages)
                if reply:
                    if provider != self._provider.get():
                        self._append_msg("system",
                            f"Auto-switched to {provider} (primary provider failed)")
                    self._history.append({"role":"assistant","content": reply})
                    self._typewrite(reply, provider)
                    self._log_dialog(self._history[-2]["content"], reply, provider)
                    self._thinking = False
                    return
            except Exception as e:
                last_error = e
                continue
        err = f" All providers failed. Last error: {last_error}"
        self._replace_last(err)
        self._thinking = False

    def _call(self, provider: str, messages: list) -> str:
        if provider == "Claude":   return self._call_claude(messages)
        elif provider == "Gemini": return self._call_gemini(messages)
        elif provider == "OpenAI": return self._call_openai(messages)
        raise ValueError(f"Unknown provider: {provider}")

    def _call_claude(self, messages):
        import json as _json
        api_key = CFG.get("ai_api_key","").strip()
        if not api_key: raise ValueError("No Claude key")
        payload = _json.dumps({
            "model": self.PROVIDERS["Claude"]["model"],
            "max_tokens": 1500,
            "system": self._system_prompt(),
            "messages": messages[-20:],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=payload,
            headers={"Content-Type":"application/json","x-api-key":api_key,
                     "anthropic-version":"2023-06-01"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read())
        return data["content"][0]["text"]

    def _call_gemini(self, messages):
        import json as _json
        api_key = CFG.get("gemini_api_key","").strip()
        if not api_key: raise ValueError("No Gemini key")
        contents = []
        for m in messages[-20:]:
            role = "user" if m["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})
        payload = _json.dumps({
            "system_instruction": {"parts": [{"text": self._system_prompt()}]},
            "contents": contents,
            "generationConfig": {"maxOutputTokens": 1500, "temperature": 0.4},
        }).encode()
        model = self.PROVIDERS["Gemini"]["model"]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type":"application/json", "User-Agent":"SOC-Sentinel/1.0"}, method="POST")
        # Retry transient errors (503, 429) with exponential backoff
        import urllib.error as _uerr, time as _time, logging as _log
        max_attempts = 3
        backoff = 1.0
        last_exc = None
        for attempt in range(1, max_attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = _json.loads(resp.read())
                last_exc = None
                break
            except Exception as e:
                last_exc = e
                if isinstance(e, _uerr.HTTPError):
                    try:
                        body = e.read().decode(errors="ignore")
                    except Exception:
                        body = "<failed to read body>"
                    _log.error("Gemini HTTPError (attempt %s/%s): code=%s reason=%s body=%s", attempt, max_attempts, getattr(e, 'code', ''), getattr(e, 'reason', ''), body)
                    # Retry on 503 Service Unavailable or 429 Too Many Requests
                    if getattr(e, 'code', None) in (429, 503) and attempt < max_attempts:
                        _time.sleep(backoff)
                        backoff *= 2
                        continue
                    raise
                else:
                    _log.exception("Gemini request failed (attempt %s/%s)", attempt, max_attempts)
                    if attempt < max_attempts:
                        _time.sleep(backoff)
                        backoff *= 2
                        continue
                    raise
        return (data.get("candidates",[{}])[0].get("content",{})
                    .get("parts",[{}])[0].get("text",""))

    def _call_openai(self, messages):
        import json as _json
        api_key = CFG.get("openai_api_key","").strip()
        if not api_key: raise ValueError("No OpenAI key")
        msgs = [{"role":"system","content": self._system_prompt()}] + messages[-20:]
        payload = _json.dumps({
            "model": self.PROVIDERS["OpenAI"]["model"],
            "max_tokens": 1500, "temperature": 0.4, "messages": msgs,
        }).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions", data=payload,
            headers={"Content-Type":"application/json",
                     "Authorization":f"Bearer {api_key}"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _system_prompt(self):
        mode = "SIMULATION (synthetic data)" if CFG.get("demo_mode") else "LIVE CAPTURE (real traffic)"
        return (f"You are an expert SOC analyst AI embedded in SOC Sentinel ({mode}). "
                f"You ONLY work with the data provided. Never invent statistics. "
                f"Be concise, accurate, and security-focused.")

    def _typewrite(self, full_text: str, provider: str):
        self._replace_last("")
        icon   = self.PROVIDERS.get(provider, {}).get("icon","")
        prefix = f"\nASSISTANT [{provider}]\n"
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", prefix, "ai")
        self.chat_box.configure(state="disabled")
        words = full_text.split(" ")
        pos   = [0]
        def _next_word():
            if not self.winfo_exists(): return
            if pos[0] >= len(words):
                self.chat_box.configure(state="normal")
                self.chat_box.insert("end", "\n", "ai")
                self.chat_box.see("end")
                self.chat_box.configure(state="disabled")
                self.chat_box.tag_config("ai",   foreground=T["safe"])
                self.chat_box.tag_config("user", foreground=T["accent"])
                self.chat_box.tag_config("sys",  foreground=T["warn"])
                return
            chunk = words[pos[0]] + " "
            self.chat_box.configure(state="normal")
            self.chat_box.insert("end", chunk, "ai")
            self.chat_box.see("end")
            self.chat_box.configure(state="disabled")
            pos[0] += 1
            delay = max(8, min(30, 600 // max(len(words), 1)))
            self._stream_after = self.after(delay, _next_word)
        _next_word()

    def _append_msg(self, role, text):
        self.chat_box.configure(state="normal")
        provider = self._provider.get()
        if role == "user":
            self.chat_box.insert("end", f"\n YOU\n{text}\n", "user")
        elif role == "assistant":
            self.chat_box.insert("end", f"\nASSISTANT\n{text}\n", "ai")
        else:
            self.chat_box.insert("end", f"\n{text}\n", "sys")
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")
        self.chat_box.tag_config("user", foreground=T["accent"])
        self.chat_box.tag_config("ai",   foreground=T["safe"])
        self.chat_box.tag_config("sys",  foreground=T["warn"])

    def _replace_last(self, new_text):
        try:
            self.chat_box.configure(state="normal")
            content = self.chat_box.get("1.0","end")
            match = None
            for m in re.finditer(r'\nASSISTANT', content):
                match = m
            if match:
                lines_before = content[:match.start()].count("\n")
                self.chat_box.delete(f"{lines_before+1}.0","end")
                if new_text:
                    self.chat_box.insert("end",
                        f"\nASSISTANT\n{new_text}\n", "ai")
            else:
                if new_text: self._append_msg("assistant", new_text)
            self.chat_box.see("end")
            self.chat_box.configure(state="disabled")
        except Exception:
            if new_text: self._append_msg("assistant", new_text)

    def _clear_chat(self):
        if self._stream_after:
            try: self.after_cancel(self._stream_after)
            except Exception: pass
        self._history.clear()
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0","end")
        self.chat_box.configure(state="disabled")
        self._append_msg("assistant", tr("chat_cleared"))

    def _log_dialog(self, user_msg: str, ai_reply: str, provider: str):
        if not CFG.get("ai_log_dialogs", True): return
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                ts = datetime.now().isoformat(timespec="seconds")
                f.write(f"\n[{ts}] [{provider}]\n"
                        f"USER: {user_msg[:300]}\n"
                        f"AI:   {ai_reply[:500]}\n"
                        f"{''*60}\n")
        except Exception: pass

class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine       = engine
        self._net_prev    = psutil.net_io_counters()
        self._bw_hist     = collections.deque([0]*60, maxlen=60)
        self._pps_hist    = collections.deque([0]*60, maxlen=60)
        self._pkt_prev    = 0
        self._threat_hist = collections.deque([0]*60, maxlen=60)
        self._tcp_hist    = collections.deque([0]*60, maxlen=60)
        self._udp_hist    = collections.deque([0]*60, maxlen=60)
        self._icmp_hist   = collections.deque([0]*60, maxlen=60)
        self._proto_prev  = {"TCP":0,"UDP":0,"ICMP":0}
        self._last_fig_draw = 0.0
        self._fig_interval  = 3.0
        self._bg_map = {}
        self._blit_supported = False
        self._last_protos   = None
        self._last_apps     = None
        self._bw_fill       = None
        self._build()
        self._tick()

    def _build(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, pady=(8,8))

        kpi_container = ctk.CTkFrame(scroll, fg_color="transparent")
        kpi_container.pack(fill="x", pady=(20,10), padx=20)
        ctk.CTkButton(kpi_container, text="", width=30, height=30, fg_color=T["bg_card"],
                      command=lambda: kpi_canvas.xview_scroll(-1,"units")
                      ).pack(side="left", padx=(4,8))
        kpi_canvas = tk.Canvas(kpi_container, height=120, bg=T["bg_deep"], highlightthickness=0)
        kpi_canvas.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(kpi_container, text="", width=30, height=30, fg_color=T["bg_card"],
                      command=lambda: kpi_canvas.xview_scroll(1,"units")
                      ).pack(side="left", padx=(8,4))
        kpi_inner = ctk.CTkFrame(kpi_canvas, fg_color="transparent")
        kpi_canvas.create_window((0,0), window=kpi_inner, anchor="nw")

        self.c_pkts    = KPICard(kpi_inner, tr("total_packets"),"0",     T["accent"],        "", tr("captured"))
        self.c_threats = KPICard(kpi_inner, tr("threats"),       "0",     T["danger"],        "", tr("detected"))
        self.c_blocked = KPICard(kpi_inner, tr("blocked_ips"),   "0",     T["accent_purple"], "", tr("blocks"))
        self.c_speed   = KPICard(kpi_inner, tr("net_speed"),     "0 B/s", T["safe"],          "", tr("in+out"))
        self.c_alerts  = KPICard(kpi_inner, tr("alerts_min"),    "0",     T["accent_orange"], "", tr("last_60s"))
        self.c_conns   = KPICard(kpi_inner, tr("conns"),         "0",     T["accent_purple"], "", tr("active"))
        self.c_dns     = KPICard(kpi_inner, tr("dns"),           "0",     T["info"],          "", tr("queries"))
        self.c_arp     = KPICard(kpi_inner, tr("arp_hosts"),     "0",     T["accent"],        "", tr("found"))
        self.c_cpu     = KPICard(kpi_inner, tr("cpu_pct"),       "0%",    T["safe"],          "", tr("usage"))
        self.c_mem     = KPICard(kpi_inner, tr("mem_pct"),       "0%",    T["warn"],          "", tr("used"))
        for c in [self.c_pkts,self.c_threats,self.c_blocked,self.c_speed,self.c_alerts,
                  self.c_conns,self.c_dns,self.c_arp,self.c_cpu,self.c_mem]:
            c.pack(side="left", padx=8, pady=4)
        kpi_inner.bind("<Configure>",
                       lambda e: kpi_canvas.configure(scrollregion=kpi_canvas.bbox("all")))

        self._mode_banner = ctk.CTkLabel(scroll, text="", font=FONT_SMALL,
                                          text_color=T["bg_deep"], fg_color="transparent",
                                          corner_radius=6)
        self._mode_banner.pack(pady=(0,6))
        self._refresh_mode_banner()

        mid = ctk.CTkFrame(scroll, fg_color="transparent")
        mid.pack(fill="both", expand=True, pady=(0,10), padx=20)

        left = ctk.CTkFrame(mid, fg_color=T["bg_panel"], corner_radius=14)
        left.pack(side="left", fill="both", expand=True, padx=(0,8))

        section_label(left, tr("bandwidth"), tr("bandwidth_sub"))
        self.fig_bw, self.ax_bw, _ = self._make_fig(left, (7,1.8))
        self._bw_line, = self.ax_bw.plot(range(60),[0]*60, color=_adjust_color(T["accent"],0.98), lw=2.4)

        section_label(left, tr("packet_rate"), tr("packet_rate_sub"))
        self.fig_pps, self.ax_pps, _ = self._make_fig(left, (7,1.6))
        self._pps_line, = self.ax_pps.plot(range(60),[0]*60, color=_adjust_color(T["safe"],0.98), lw=2.0)

        section_label(left, tr("protocol_rate"), tr("protocol_rate_sub"))
        self.fig_proto, self.ax_proto, _ = self._make_fig(left, (7,1.8))
        self._tcp_line,  = self.ax_proto.plot(range(60),[0]*60, color=_adjust_color(T["accent"],0.98),
                                               lw=2.0, label="TCP")
        self._udp_line,  = self.ax_proto.plot(range(60),[0]*60, color=_adjust_color(T["safe"],0.98),
                                               lw=2.0, label="UDP")
        self._icmp_line, = self.ax_proto.plot(range(60),[0]*60, color=_adjust_color(T["danger"],0.98),
                                               lw=1.6, linestyle="--", label="ICMP")
        self.ax_proto.legend(loc="upper right", fontsize=6,
                              facecolor=T["bg_card"], labelcolor=T["text_dim"],
                              framealpha=0.7)

        section_label(left, tr("threat_rate"), tr("threat_rate"))
        self.fig_thr, self.ax_thr, _ = self._make_fig(left, (7,1.6))
        self._thr_line, = self.ax_thr.plot(range(60),[0]*60, color=T["danger"], lw=1.5)

        right = ctk.CTkFrame(mid, fg_color=T["bg_panel"], corner_radius=14, width=340)
        right.pack(side="right", fill="both", padx=(8,0))
        right.pack_propagate(False)

        section_label(right, tr("protocols"), tr("distribution"))
        self.fig_pie = plt.Figure(figsize=(3.4,2.8), facecolor=T["mpl_bg"])
        self.ax_pie  = self.fig_pie.add_subplot(111)
        self.ax_pie.set_facecolor(T["mpl_bg"])
        self.fig_pie.subplots_adjust(left=0.05,right=0.95,top=0.95,bottom=0.05)
        make_canvas(right, self.fig_pie)

        section_label(right, tr("top_apps"), tr("by_packets"))
        self.fig_bar = plt.Figure(figsize=(3.4,2.6), facecolor=T["mpl_bg"])
        self.ax_bar  = self.fig_bar.add_subplot(111)
        self.ax_bar.set_facecolor(T["mpl_bg"])
        self.fig_bar.subplots_adjust(left=0.32,right=0.97,top=0.97,bottom=0.08)
        make_canvas(right, self.fig_bar)

        bot = ctk.CTkFrame(scroll, fg_color=T["bg_panel"], corner_radius=14)
        bot.pack(fill="x", pady=(0,20), padx=20)
        section_label(bot, tr("recent_connections"), tr("live_stream"))
        cols = ("time","src","dst","app","size","status")
        self.live_tree = ttk.Treeview(bot, columns=cols, show="headings",
                                       style="Sentinel.Treeview", height=5)
        for col, w in zip(cols,[80,140,140,120,70,130]):
            self.live_tree.heading(col, text=tr("col_"+col))
            self.live_tree.column(col, width=w, anchor="w")
        self.live_tree.tag_configure("critical", foreground="#FF3B5C")
        self.live_tree.tag_configure("high",     foreground="#FFCC00")
        self.live_tree.tag_configure("danger",   foreground=T["danger"])
        self.live_tree.tag_configure("safe",     foreground="#00FF88")
        self.live_tree.tag_configure("info",     foreground=T["info"])
        sb = ttk.Scrollbar(bot, orient="vertical", command=self.live_tree.yview)
        self.live_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", padx=(0,4), pady=4)
        self.live_tree.pack(fill="x", padx=8, pady=(0,12))

    def _refresh_mode_banner(self):
        if CFG.get("demo_mode"):
            self._mode_banner.configure(text=f"    {tr('simulation_mode')}  ",
                                         fg_color=T["warn"], text_color=T["bg_deep"])
        else:
            self._mode_banner.configure(text=f"{tr('live_mode')}",
                                         fg_color=T["safe"], text_color=T["bg_deep"])

    def _make_fig(self, parent, figsize):
        fig = plt.Figure(figsize=figsize, facecolor=T["mpl_bg"])
        ax  = fig.add_subplot(111); ax.set_facecolor(T["mpl_bg"])
        ax.tick_params(colors=T["text_dim"], labelsize=7)
        for sp in ax.spines.values():
            try: sp.set_visible(False)
            except Exception: pass
        ax.set_xlim(0,59); ax.set_ylim(0,1)
        fig.subplots_adjust(left=0.07,right=0.99,top=0.95,bottom=0.15)
        c = make_canvas(parent, fig)
        self._blit_supported = False
        return fig, ax, c

    def _draw_pie(self, protos):
        try:
            self.ax_pie.clear(); self.ax_pie.set_facecolor(T["mpl_bg"])
        except Exception: return
        pie_colors = [T["accent"],T["safe"],T["warn"],T["danger"],
                      T["accent_purple"],T["accent_orange"]]
        labels = list(protos.keys()); sizes = list(protos.values())
        if not sizes: return
        self.ax_pie.pie(sizes, labels=labels, autopct="%1.0f%%",
                        colors=pie_colors[:len(labels)],
                        textprops={"color":T["text_dim"],"fontsize":7},
                        startangle=90, pctdistance=0.75,
                        wedgeprops={"linewidth":1.5,"edgecolor":T["bg_panel"]})
        try: self.fig_pie.canvas.draw_idle()
        except Exception: pass

    def _draw_bar(self, apps):
        try:
            self.ax_bar.clear(); self.ax_bar.set_facecolor(T["mpl_bg"])
        except Exception: return
        top = sorted(apps.items(), key=lambda x: x[1], reverse=True)[:7]
        if not top: return
        names = [x[0][:12] for x in top]; vals = [x[1] for x in top]
        bars = self.ax_bar.barh(names, vals, color=T["accent"], height=0.55)
        for b in bars: b.set_alpha(0.82)
        self.ax_bar.tick_params(colors=T["text_dim"], labelsize=7)
        for sp in self.ax_bar.spines.values(): sp.set_color(T["border"])
        try: self.fig_bar.canvas.draw_idle()
        except Exception: pass

    def add_live_row(self, src, dst, app, size, status):
        app_up    = (app or "").upper()
        status_up = (status or "").upper()
        is_wifi   = "" in (app or "") or "802.11" in (app or "")
        if is_wifi or "" in status or "" in (app or ""):
            if any(k in app_up or k in status_up for k in ("DEAUTH","EVIL","MITM","CRITICAL","FLOOD")):
                tag = "critical"
            else:
                tag = "high"
        elif "BLOCKED" in status_up:
            tag = "danger"
        elif "SAFE" not in status_up and "ICMP" not in status_up:
            tag = "danger"
        elif "ICMP" in status_up:
            tag = "info"
        else:
            tag = "safe"
        t = datetime.now().strftime("%H:%M:%S")
        self.live_tree.insert("",0, values=(t,src,dst,app,f"{size}B",status), tags=(tag,))
        ch = self.live_tree.get_children()
        if len(ch) > 50: self.live_tree.delete(ch[-1])

    def _tick(self):
        try: self._update()
        except Exception: pass
        self.after(2000, self._tick)

    def _update(self):
        stats, protos, apps = self.engine.get_stats()
        total = stats.get("total", 0)

        cur  = psutil.net_io_counters(); prev = self._net_prev
        bw   = ((cur.bytes_sent-prev.bytes_sent) +
                (cur.bytes_recv-prev.bytes_recv)) / 1024
        self._net_prev = cur
        self._bw_hist.append(bw)

        pps = max(total - self._pkt_prev, 0); self._pkt_prev = total
        self._pps_hist.append(pps)

        tcp_now  = protos.get("TCP", 0)
        udp_now  = protos.get("UDP", 0)
        icmp_now = protos.get("ICMP",0)
        self._tcp_hist.append( max(tcp_now  - self._proto_prev["TCP"],  0))
        self._udp_hist.append( max(udp_now  - self._proto_prev["UDP"],  0))
        self._icmp_hist.append(max(icmp_now - self._proto_prev["ICMP"], 0))
        self._proto_prev = {"TCP":tcp_now,"UDP":udp_now,"ICMP":icmp_now}

        now = datetime.now()
        recent_alerts = []
        for a in self.engine.alerts:
            try:
                at = datetime.strptime(a["time"],"%H:%M:%S").replace(
                    year=now.year, month=now.month, day=now.day)
                diff = (now - at).total_seconds()
                if diff < 0: diff += 86400
                if diff < 60: recent_alerts.append(a)
            except Exception: pass

        per_sec = sum(1 for a in self.engine.alerts
                      if self._alert_age(a, now) < 1)
        self._threat_hist.append(per_sec)

        bw_str = f"{bw:.1f} KB/s" if bw < 1024 else f"{bw/1024:.2f} MB/s"
        self.c_pkts.set(f"{total:,}")
        self.c_threats.set(str(self.engine.threat_count))
        self.c_blocked.set(str(len(self.engine.blocked_ips)))
        self.c_speed.set(bw_str)
        self.c_alerts.set(str(len(recent_alerts)))
        try: self.c_conns.set(str(len(self.engine.proc_map)))
        except Exception: pass
        try: self.c_dns.set(str(protos.get("DNS",0)))
        except Exception: pass
        try: self.c_arp.set(str(len(self.engine.arp_table)))
        except Exception: pass
        try:
            self.c_cpu.set(f"{psutil.cpu_percent():.0f}%")
            self.c_mem.set(f"{psutil.virtual_memory().percent:.0f}%")
        except Exception: pass

        bwd  = list(self._bw_hist); ppsd = list(self._pps_hist)
        thrd = list(self._threat_hist)
        tcpd = list(self._tcp_hist); udpd = list(self._udp_hist)
        icmpd= list(self._icmp_hist)
        self._bw_line.set_ydata(smooth_list(bwd, window=5));    self.ax_bw.set_ylim(0,max(max(bwd),1)*1.25)
        self._pps_line.set_ydata(smooth_list(ppsd, window=3));  self.ax_pps.set_ylim(0,max(max(ppsd),1)*1.25)
        self._thr_line.set_ydata(thrd);  self.ax_thr.set_ylim(0,max(max(thrd),1)*1.25)
        self._tcp_line.set_ydata(smooth_list(tcpd, window=3))
        self._udp_line.set_ydata(smooth_list(udpd, window=3))
        self._icmp_line.set_ydata(smooth_list(icmpd, window=3))
        proto_max = max(max(tcpd),max(udpd),max(icmpd),1)*1.25
        self.ax_proto.set_ylim(0, proto_max)

        now_ts = time.time()
        if now_ts - self._last_fig_draw >= self._fig_interval:
            try:
                if self._bw_fill: self._bw_fill.remove()
                self._bw_fill = self.ax_bw.fill_between(range(60), bwd,
                                                          color=T["accent"], alpha=0.12)
                self.fig_bw.canvas.draw_idle()
            except Exception: pass
            try: self.fig_pps.canvas.draw_idle()
            except Exception: pass
            try: self.fig_proto.canvas.draw_idle()
            except Exception: pass
            try: self.fig_thr.canvas.draw_idle()
            except Exception: pass
            if protos and protos != self._last_protos:
                try: self._draw_pie(protos); self._last_protos = dict(protos)
                except Exception: pass
            if apps and apps != self._last_apps:
                try: self._draw_bar(apps); self._last_apps = dict(apps)
                except Exception: pass
            self._last_fig_draw = now_ts

    @staticmethod
    def _alert_age(alert, now):
        try:
            at = datetime.strptime(alert["time"],"%H:%M:%S").replace(
                year=now.year, month=now.month, day=now.day)
            diff = (now - at).total_seconds()
            if diff < 0: diff += 86400
            return diff
        except Exception: return 9999

class PacketRecord:

    __slots__ = ("seq", "time", "src", "dst", "proto", "app", "size", "status", "raw")

    def __init__(self, seq: int, result: dict):
        self.seq    = seq
        self.time   = result.get("time",   datetime.now().strftime("%H:%M:%S.%f")[:-3])
        self.src    = result.get("src",    "?")
        self.dst    = result.get("dst",    "?")
        self.proto  = result.get("proto",  "?")
        self.app    = result.get("app",    "?")
        self.size   = result.get("size",   0)
        self.status = result.get("status", "?")
        self.raw    = result.get("pkt",    None)

    def haystack(self) -> str:
        return f"{self.src} {self.dst} {self.proto} {self.app} {self.size} {self.status}"

    def get(self, key, default=None):
        return getattr(self, key, default)

class AnalyzerPage(ctk.CTkFrame):

    _UI_ROW_LIMIT = 150
    _FLUSH_MS     = 150
    _GC_MS        = 60_000

    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine
        self._incoming: collections.deque = collections.deque()
        self._records: collections.deque = collections.deque(maxlen=3000)
        self._displayed: list = []
        self._count = 0
        self._build()
        self._schedule_flush()
        self._schedule_gc()

    def _build(self):
        tb = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=10)
        tb.pack(fill="x", padx=20, pady=(20, 6))

        ctk.CTkLabel(tb, text=tr("filter"), font=FONT_SMALL,
                     text_color=T["text_dim"]).pack(side="left", padx=(14, 4), pady=10)

        self.flt = tk.StringVar()
        self.flt_entry = ctk.CTkEntry(
            tb, textvariable=self.flt, width=220, font=FONT_MONO,
            fg_color=T["bg_card"], border_color=T["border"],
            text_color=T["text_primary"],
            placeholder_text=tr("filter_placeholder"),
            corner_radius=8,
        )
        self.flt_entry.pack(side="left", padx=4)
        self.flt_entry.bind("<Return>", lambda e: self._apply_filter())

        self._use_regex = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            tb, text=tr("regex"), variable=self._use_regex,
            font=FONT_SMALL, text_color=T["text_dim"],
        ).pack(side="left", padx=6)

        self.paused = tk.BooleanVar(value=False)
        ctk.CTkSwitch(
            tb, text=tr("pause"), variable=self.paused,
            font=FONT_SMALL, text_color=T["text_dim"],
            progress_color=T["warn"],
        ).pack(side="left", padx=14)

        self.cnt_lbl = ctk.CTkLabel(
            tb, text=f"0 {tr('packets')}", font=FONT_SMALL, text_color=T["text_dim"])
        self.cnt_lbl.pack(side="right", padx=10)

        ctk.CTkButton(
            tb, text=tr("export"), width=80, font=FONT_SMALL,
            fg_color=T["accent"], text_color=T["bg_panel"],
            command=self._export,
        ).pack(side="right", padx=6)

        ctk.CTkButton(
            tb, text=tr("clear"), width=80, font=FONT_SMALL,
            fg_color=T["bg_card"], text_color=T["text_dim"],
            command=self._clear,
        ).pack(side="right", padx=6)

        tbl_f = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        tbl_f.pack(fill="both", expand=True, padx=20, pady=(0, 6))

        cols = ("#", "time", "src", "dst", "proto", "app", "size", "status")
        self.tree = ttk.Treeview(
            tbl_f, columns=cols, show="headings", style="Sentinel.Treeview")
        for col, w in zip(cols, [40, 90, 145, 145, 60, 130, 65, 130]):
            col_key = "col_hash" if col == "#" else "col_" + col
            self.tree.heading(col, text=tr(col_key))
            self.tree.column(col, width=w, anchor="w")

        for tag, color in [
            ("safe",     "#00FF88"),
            ("danger",   T["danger"]),
            ("info",     T["info"]),
            ("blocked",  T["accent_purple"]),
            ("critical", "#FF3B5C"),
            ("high",     "#FFCC00"),
        ]:
            self.tree.tag_configure(tag, foreground=color)

        sb = ttk.Scrollbar(tbl_f, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self._inspect)

        insp_f = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        insp_f.pack(fill="x", padx=20, pady=(0, 20))
        section_label(insp_f, tr("packet_inspector"), tr("click_a_row_above"))

        self.tabs = ctk.CTkTabview(
            insp_f, fg_color=T["bg_card"],
            segmented_button_fg_color=T["bg_card"],
            segmented_button_selected_color=T["accent"],
            segmented_button_selected_hover_color=T["accent"],
            segmented_button_unselected_color=T["bg_card"],
            text_color=T["text_primary"],
        )
        self.tabs.pack(fill="x", padx=10, pady=(0, 12))

        _lyr = tr("layers"); _hex = tr("hex_dump"); _thr = tr("threats")
        for t in (_lyr, _hex, _thr):
            self.tabs.add(t)

        def _make_box(tab, text_color=None):
            b = ctk.CTkTextbox(
                tab, height=120, fg_color=T["bg_panel"],
                text_color=text_color or T["safe"],
                font=("Courier New", 9),
            )
            b.pack(fill="both", expand=True, padx=4, pady=4)
            def _guard(e):
                if (e.state & 0x4) and e.keysym.lower() in ("c", "a"):
                    return
                return "break"
            b.bind("<Key>", _guard)
            menu = tk.Menu(b, tearoff=0)
            menu.add_command(label="Copy",     command=lambda: self._copy_sel(b))
            menu.add_command(label="Copy All", command=lambda: self._copy_all(b))
            b.bind("<Button-3>", lambda e: (menu.tk_popup(e.x_root, e.y_root), menu.grab_release()))
            return b

        self.tb_layers  = _make_box(self.tabs.tab(_lyr))
        self.tb_hex     = _make_box(self.tabs.tab(_hex), T["accent"])
        self.tb_threats = _make_box(self.tabs.tab(_thr), T["danger"])

    def add_packet(self, result: dict):
        if self.paused.get(): return
        flt = self.flt.get().strip()
        if flt:
            hay = (f"{result.get('src','')} {result.get('dst','')} "
                   f"{result.get('proto','')} {result.get('app','')} "
                   f"{result.get('size',0)} {result.get('status','')}")
            if not self._match_text(hay, flt): return
        self._count += 1
        rec = PacketRecord(self._count, result)
        self._records.append(rec)
        self._incoming.append(rec)

    def _schedule_flush(self):
        self.after(self._FLUSH_MS, self._flush_batch)

    def _flush_batch(self):
        try:
            if self._incoming:
                batch = []
                while self._incoming:
                    batch.append(self._incoming.popleft())
                for rec in batch:
                    self._insert_row(rec)
                self.cnt_lbl.configure(text=f"{self._count} {tr('packets')}")
        except Exception:
            logging.exception("[AnalyzerPage] _flush_batch error")
        finally:
            self.after(self._FLUSH_MS, self._flush_batch)

    def _insert_row(self, rec: "PacketRecord"):
        children = self.tree.get_children()
        while len(children) >= self._UI_ROW_LIMIT:
            self.tree.delete(children[-1])
            if self._displayed: self._displayed.pop()
            children = self.tree.get_children()
        self.tree.insert(
            "", "0",
            values=(rec.seq, rec.time, rec.src, rec.dst,
                    rec.proto, rec.app, f"{rec.size}B", rec.status),
            tags=(self._tag_for(rec),),
        )
        self._displayed.insert(0, rec)

    def _export(self):
        try:
            # Let user choose the format
            import tkinter as tk
            from tkinter import simpledialog
            choice = simpledialog.askstring(
                tr("export"),
                "Choose format: JSON, PDF, or CSV (default: CSV)",
                parent=self
            )
            choice = (choice or "csv").strip().lower()
            
            if choice in ["json", "pdf"]:
                # Export incidents/alerts
                path = filedialog.asksaveasfilename(
                    defaultextension=f".{choice}",
                    filetypes=[
                        (f"{choice.upper()} files", f"*.{choice}"),
                        ("All files", "*.*")
                    ],
                )
                if not path:
                    return
                if choice == "json":
                    from utils.report_export import export_json
                    export_json(path, self.engine.alerts)
                else:  # pdf
                    from utils.report_export import export_pdf
                    export_pdf(path, self.engine.alerts)
                messagebox.showinfo(tr("export"), f"Incidents exported to {path}")
            else:
                # Original CSV export of packets
                path = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    filetypes=[("CSV", "*.csv"), ("All", "*.*")],
                )
                if not path:
                    return
                rows = [self.tree.item(iid)["values"]
                        for iid in self.tree.get_children()]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["#", "time", "src", "dst", "proto", "app", "size", "status"])
                    w.writerows(rows)
                messagebox.showinfo(tr("export"), f"{len(rows)} rows saved.\n{path}")
        except Exception:
            logging.exception("[AnalyzerPage] _export error")

    def _clear(self):
        for iid in self.tree.get_children(): self.tree.delete(iid)
        self._incoming.clear(); self._records.clear(); self._displayed.clear()
        self._count = 0
        for box in (self.tb_layers, self.tb_hex, self.tb_threats):
            self._fill_box(box, "")
        self.cnt_lbl.configure(text=f"0 {tr('packets')}")

    def _inspect(self, _event=None):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        if idx >= len(self._displayed): return
        rec = self._displayed[idx]
        if SCAPY_AVAILABLE and rec.raw is not None and hasattr(rec.raw, "haslayer"):
            pkt = rec.raw
            self._fill_box(self.tb_layers, pkt.show(dump=True))
            self._fill_box(self.tb_hex,    scapy.hexdump(pkt, dump=True))
            src_ip = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else rec.src
        else:
            self._fill_box(
                self.tb_layers,
                f"SRC:    {rec.src}\n"
                f"DST:    {rec.dst}\n"
                f"PROTO:  {rec.proto}\n"
                f"APP:    {rec.app}\n"
                f"SIZE:   {rec.size} bytes\n"
                f"STATUS: {rec.status}\n"
                f"TIME:   {rec.time}",
            )
            self._fill_box(self.tb_hex, f"[{tr('simulation_mode')}]")
            src_ip = rec.src
        try:
            related = [a for a in self.engine.alerts if a.get("actor") == src_ip][-15:]
            txt = (
                f"  {len(related)} threats from {src_ip}:\n\n"
                + "".join(
                    f"  [{a['time']}]  {a['type']}    {a['severity']}\n"
                    for a in related
                )
                if related else f"  No threats from {src_ip}"
            )
        except Exception:
            txt = "  Error loading threats"
        self._fill_box(self.tb_threats, txt)

    def _apply_filter(self):
        flt = self.flt.get().strip()
        for iid in self.tree.get_children(): self.tree.delete(iid)
        self._displayed.clear()
        kv: dict = {}; terms: list = []
        for tok in flt.split():
            if "=" in tok:
                k, v = tok.split("=", 1); kv[k.strip().lower()] = v.strip()
            else:
                terms.append(tok)
        inserted = []
        for rec in reversed(self._records):
            if not self._match_record(rec, flt, kv, terms): continue
            iid = self.tree.insert(
                "", "end",
                values=("", rec.time, rec.src, rec.dst,
                        rec.proto, rec.app, f"{rec.size}B", rec.status),
                tags=(self._tag_for(rec),),
            )
            self._displayed.append(rec); inserted.append(iid)
        if inserted:
            try:
                self.tree.selection_set(inserted[0])
                self.tree.focus(inserted[0]); self.tree.see(inserted[0])
            except Exception: pass
        self.cnt_lbl.configure(text=f"{self._count} pkts")

    def _schedule_gc(self):
        self.after(self._GC_MS, self._run_gc)

    def _run_gc(self):
        try: gc.collect()
        except Exception: pass
        self.after(self._GC_MS, self._run_gc)

    def _match_text(self, haystack: str, pattern: str) -> bool:
        try:
            if self._use_regex.get():
                return bool(re.search(pattern, haystack, re.IGNORECASE))
            return pattern.lower() in haystack.lower()
        except re.error:
            return pattern.lower() in haystack.lower()

    def _match_record(self, rec: "PacketRecord", flt: str, kv: dict, terms: list) -> bool:
        if not flt: return True
        fields = {"src": rec.src, "dst": rec.dst, "proto": rec.proto,
                  "app": rec.app, "status": rec.status, "size": str(rec.size)}
        for key, val in kv.items():
            if not self._match_text(fields.get(key, ""), val): return False
        if terms:
            hay = rec.haystack()
            for term in terms:
                if not self._match_text(hay, term): return False
        return True

    @staticmethod
    def _tag_for(rec: "PacketRecord") -> str:
        app_up    = (rec.app or "").upper()
        status_up = (rec.status or "").upper()
        is_wifi   = "" in (rec.app or "") or rec.proto == "802.11"
        if is_wifi or "" in rec.status or "" in (rec.app or ""):
            if any(k in app_up or k in status_up for k in ("DEAUTH","EVIL","MITM","CRITICAL","FLOOD")):
                return "critical"
            return "high"
        if "BLOCKED" in status_up: return "blocked"
        if "SAFE" not in status_up: return "danger"
        if rec.proto == "ICMP": return "info"
        return "safe"

    def _fill_box(self, box, text: str):
        try:
            box.configure(state="normal"); box.delete("0.0", "end")
            if text: box.insert("end", text)
            box.configure(state="disabled")
        except Exception: pass

    def _copy_sel(self, box):
        try:
            s = box.get("sel.first", "sel.last")
            self.clipboard_clear(); self.clipboard_append(s)
        except Exception: pass

    def _copy_all(self, box):
        try:
            self.clipboard_clear(); self.clipboard_append(box.get("1.0", "end"))
        except Exception: pass

class ThreatPage(ctk.CTkFrame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine; self._build()
        for a in engine.alerts[-300:]: self._on_alert(a)
        engine.alert_callbacks.append(self._on_alert); self._tick()

    def _build(self):
        krow = ctk.CTkFrame(self, fg_color="transparent")
        krow.pack(fill="x", padx=20, pady=(20,10))
        self.sev_cards = {}
        for sev, color, icon in [("critical",T["danger"],""),
                                   ("high",T["accent_orange"],""),
                                   ("medium",T["warn"],""),
                                   ("low",T["info"],"")]:
            c = KPICard(krow, tr(sev), "0", color, "")
            c.pack(side="left",expand=True,fill="both",padx=5)
            self.sev_cards[sev] = c

        top = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        top.pack(fill="both",expand=True,padx=20,pady=(0,8))
        section_label(top, tr('live_threat_feed'), tr('realtime_events'))
        cols = ("time","type","actor","severity","size","action")
        self.atree = ttk.Treeview(top, columns=cols, show="headings",
                                   style="Alert.Treeview")
        for col,w in zip(cols,[90,160,155,90,75,120]):
            self.atree.heading(col,text=tr("col_"+col)); self.atree.column(col,width=w,anchor="w")
        for sev,clr in [("critical",T["danger"]),("high",T["accent_orange"]),
                         ("medium",T["warn"]),("low",T["info"])]:
            self.atree.tag_configure(sev.upper(), foreground=clr)
        asb = ttk.Scrollbar(top, orient="vertical", command=self.atree.yview)
        self.atree.configure(yscrollcommand=asb.set)
        asb.pack(side="right",fill="y",padx=(0,4))
        self.atree.pack(fill="both",expand=True,padx=4,pady=(0,8))
        self.atree.bind("<<TreeviewSelect>>", self._sel_alert)

        bot = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        bot.pack(fill="x",padx=20,pady=(0,20))
        section_label(bot, tr('ip_control'), tr('manual_block_unblock'))
        row = ctk.CTkFrame(bot, fg_color="transparent"); row.pack(fill="x",padx=16,pady=(0,10))
        self.ip_ent = ctk.CTkEntry(row, width=200, placeholder_text=tr("ip_address_placeholder"),
                                    fg_color=T["bg_card"], border_color=T["border"],
                                    text_color=T["text_primary"], font=FONT_MONO, corner_radius=8)
        self.ip_ent.pack(side="left",padx=(0,10))
        ctk.CTkButton(row, text=f"  {tr('block')}", width=110, fg_color=T["danger"], text_color="white",
                      font=FONT_SMALL, corner_radius=DEFAULT_CORNER, command=self._block).pack(side="left",padx=4)
        ctk.CTkButton(row, text=f"  {tr('unblock')}", width=110, fg_color=T["safe"],
                      text_color=T["bg_deep"], font=FONT_SMALL, corner_radius=DEFAULT_CORNER,
                      command=self._unblock).pack(side="left",padx=4)
        ctk.CTkButton(row, text=f"  {tr('check_ip')}", width=110, fg_color=T["accent"],
                      text_color=T["bg_deep"], font=FONT_SMALL, corner_radius=DEFAULT_CORNER,
                      command=self._check_ip).pack(side="left",padx=4)
        self.blk_box = ctk.CTkTextbox(bot, height=70, fg_color=T["bg_card"],
                                       text_color=T["accent_purple"], font=FONT_MONO)
        self.blk_box.pack(fill="x",padx=16,pady=(0,14))
        self._refresh_blocked()

    def _sel_alert(self, evt):
        sel = self.atree.selection()
        if not sel: return
        item = self.atree.item(sel[0])
        vals = item["values"]
        if len(vals)>=3: self.ip_ent.delete(0,"end"); self.ip_ent.insert(0, vals[2])

    def _block(self):
        ip = self.ip_ent.get().strip()
        if not ip: messagebox.showwarning(tr('ip_control'),tr('fill_fields')); return
        self.engine.block_ip(ip); self._refresh_blocked()

    def _unblock(self):
        ip = self.ip_ent.get().strip()
        if not ip: messagebox.showwarning(tr('ip_control'),tr('fill_fields')); return
        self.engine.unblock_ip(ip); self._refresh_blocked()

    def _refresh_blocked(self):
        try:
            self.blk_box.delete(1.0, "end")
            if self.engine.blocked_ips:
                lst = "\n".join([f"  {x}" for x in sorted(self.engine.blocked_ips)])
                self.blk_box.insert(1.0, f"[BLOCKED IPS]\n{lst}")
        except Exception: pass

    def _tick(self):
        try:
            counts = collections.defaultdict(int)
            for a in self.engine.alerts[-1000:]: counts[a.get("severity","LOW").lower()] +=1
            for sev in self.sev_cards: self.sev_cards[sev].set(counts.get(sev,0))
        except Exception: pass
        self.after(1000, self._tick)

    def _check_ip(self):
        ip = self.ip_ent.get().strip()
        if not ip:
            messagebox.showwarning(tr('ip_control'), tr('fill_fields'))
            return
        threading.Thread(target=self._check_ip_thread, args=(ip,), daemon=True).start()

    def _check_ip_thread(self, ip):
        try:
            from utils.integrations import IntegrationsManager
            mgr = IntegrationsManager(CFG)
            vt_result = mgr.check_virustotal_ip(ip)
            abuseipdb_result = mgr.check_abuseipdb_ip(ip)
            self.after(0, lambda: self._show_ip_check_results(ip, vt_result, abuseipdb_result))
        except Exception as e:
            logging.exception("Failed to check IP")
            self.after(0, lambda: messagebox.showerror("Error", str(e)))

    def _show_ip_check_results(self, ip, vt_result, abuseipdb_result):
        win = ctk.CTkToplevel(self)
        win.title(f"IP Check: {ip}")
        win.geometry("700x600")
        win.resizable(True, True)
        box = ctk.CTkTextbox(win, fg_color=T["bg_card"], text_color=T["text_primary"], font=FONT_MONO)
        box.pack(fill="both", expand=True, padx=20, pady=20)
        box.insert("end", f"[IP CHECK RESULTS FOR {ip}]\n\n")
        
        if vt_result.get("error"):
            box.insert("end", f"[VirusTotal]\n{vt_result['error']}\n\n")
        else:
            stats = vt_result.get("last_analysis_stats", {})
            box.insert("end", f"[VirusTotal]\nMalicious: {stats.get('malicious',0)}\nSuspicious: {stats.get('suspicious',0)}\nHarmless: {stats.get('harmless',0)}\nUndetected: {stats.get('undetected',0)}\n\n")
        
        if abuseipdb_result.get("error"):
            box.insert("end", f"[AbuseIPDB]\n{abuseipdb_result['error']}\n\n")
        else:
            score = abuseipdb_result.get("abuseConfidenceScore", 0)
            reports = abuseipdb_result.get("totalReports", 0)
            last_report = abuseipdb_result.get("lastReportedAt", "")
            box.insert("end", f"[AbuseIPDB]\nConfidence Score: {score}\nTotal Reports: {reports}\nLast Report: {last_report}\n\n")
        
        box.configure(state="disabled")

    def _on_alert(self, a):
        def _insert():
            try:
                self.atree.insert("","0",
                    values=(a["time"],a["type"],a["actor"],a["severity"],
                            f"{a['size']}B", tr("click_to_block")), tags=(a["severity"],))
                ch = self.atree.get_children()
                if len(ch) > 500: self.atree.delete(ch[-1])
            except Exception: pass
        try: self.after(0, _insert)
        except Exception: pass
        
class ActiveBlocksPage(ctk.CTkFrame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine
        self._build()
        self._tick()
        try:
            i18n.register(self.refresh_ui)
            self.bind("<Destroy>", lambda e: i18n.unregister(self.refresh_ui))
        except Exception:
            pass

    def _build(self):
        top = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        top.pack(fill="both", expand=True, padx=20, pady=(20, 8))
        section_label(top, tr("active_blocks"), tr("active_blocks_desc"))
        cols = ("type", "target", "added")
        self.btree = ttk.Treeview(top, columns=cols, show="headings", style="Alert.Treeview")
        for col, w in zip(cols, [100, 200, 150]):
            self.btree.heading(col, text=tr("col_type") if col == "type" else tr("col_target") if col == "target" else tr("col_added"))
            self.btree.column(col, width=w, anchor="w")
        bsb = ttk.Scrollbar(top, orient="vertical", command=self.btree.yview)
        self.btree.configure(yscrollcommand=bsb.set)
        bsb.pack(side="right", fill="y", padx=(0,4))
        self.btree.pack(fill="both", expand=True, padx=4, pady=(0,8))

        bot = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        bot.pack(fill="x", padx=20, pady=(0,20))
        row = ctk.CTkFrame(bot, fg_color="transparent"); row.pack(fill="x", padx=16, pady=(10,10))
        ctk.CTkButton(row, text=f"  {tr('unblock')}", width=140, fg_color=T["accent"], text_color=T["bg_deep"],
                      font=FONT_SMALL, corner_radius=DEFAULT_CORNER, command=self._unblock_selected).pack(side="left", padx=4)
        ctk.CTkButton(row, text=f"  {tr('refresh')}", width=140, fg_color=T["bg_card"], text_color=T["text_primary"],
                      font=FONT_SMALL, corner_radius=DEFAULT_CORNER, command=self._refresh_blocks).pack(side="left", padx=4)
        self._refresh_blocks()

    def _refresh_blocks(self):
        for iid in self.btree.get_children():
            self.btree.delete(iid)
        # Get blocked IPs
        blocked_ips = set()
        if hasattr(self.engine, "blocked_ips"):
            blocked_ips.update(self.engine.blocked_ips)
        if hasattr(self.engine, "_ips") and hasattr(self.engine._ips, "blocked_ips"):
            blocked_ips.update(self.engine._ips.blocked_ips)
        for ip in sorted(blocked_ips):
            self.btree.insert("", "end", values=(tr("ip_type"), ip, "-"))
        # Get blocked MACs
        blocked_macs = set()
        if hasattr(self.engine, "_ips") and hasattr(self.engine._ips, "blocked_macs"):
            blocked_macs.update(self.engine._ips.blocked_macs)
        for mac in sorted(blocked_macs):
            self.btree.insert("", "end", values=(tr("mac_type"), mac, "-"))

    def _unblock_selected(self):
        selected = self.btree.selection()
        if not selected:
            return
        for iid in selected:
            type_, target, _ = self.btree.item(iid)["values"]
            if type_ == tr("ip_type"):
                self.engine.unblock_ip(target)
                if hasattr(self.engine, "_ips") and hasattr(self.engine._ips, "unblock_target"):
                    self.engine._ips.unblock_target(target)
            elif type_ == tr("mac_type"):
                if hasattr(self.engine, "_ips") and hasattr(self.engine._ips, "unblock_target"):
                    self.engine._ips.unblock_target(target)
        self._refresh_blocks()

    def _tick(self):
        self._refresh_blocks()
        self.after(2000, self._tick)

    def refresh_ui(self):
        try:
            # Rebuild the page to update all labels
            try:
                children = self.winfo_children()
            except Exception:
                children = []
            for widget in children:
                try: widget.destroy()
                except Exception: pass
            try: self._build()
            except Exception: pass
        except Exception as e:
            # Suppress TclError when widget is destroyed during UI rebuild
            if "_tkinter.TclError" not in str(type(e).__name__):
                logging.exception('ActiveBlocksPage refresh_ui failed')

class WebAccessPage(ctk.CTkFrame):
    def __init__(self, master, engine, app_ref, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine
        self.app_ref = app_ref
        self._build()
        self._tick()

    def _build(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, pady=8)

        # Header
        hdr = ctk.CTkFrame(scroll, fg_color=T["bg_panel"], corner_radius=14)
        hdr.pack(fill="x", padx=20, pady=(20, 12))
        ctk.CTkLabel(hdr, text=tr("web_dashboard"), font=FONT_HEADER,
                     text_color=T["accent"]).pack(pady=(16, 4))
        ctk.CTkLabel(hdr, text=tr("web_dashboard_desc"),
                     font=FONT_SMALL, text_color=T["text_dim"]).pack(pady=(0, 12))
        self._url_box = ctk.CTkTextbox(hdr, height=80, fg_color=T["bg_card"],
                                        text_color=T["safe"], font=(FONT_FAMILY_MONO, 14))
        self._url_box.pack(fill="x", padx=16, pady=(0, 8))
        brow = ctk.CTkFrame(hdr, fg_color="transparent")
        brow.pack(fill="x", padx=16, pady=(0, 16))
        ctk.CTkButton(brow, text=tr("copy"), width=140, fg_color=T["accent"],
                      text_color=T["bg_deep"], command=self._copy).pack(side="left", padx=4)
        ctk.CTkButton(brow, text=tr("open"), width=120, fg_color=T["safe"],
                      text_color=T["bg_deep"], command=self._open).pack(side="left", padx=4)

        # KPI Cards
        kpi_row = ctk.CTkFrame(scroll, fg_color="transparent")
        kpi_row.pack(fill="x", padx=20, pady=(0, 12))
        self._kpi_status = KPICard(kpi_row, tr("web_server_status"), tr("active_status"), T["safe"], "")
        self._kpi_status.pack(side="left", expand=True, fill="both", padx=5)
        self._kpi_port = KPICard(kpi_row, tr("web_port"), "5000", T["accent"], "")
        self._kpi_port.pack(side="left", expand=True, fill="both", padx=5)
        self._kpi_requests = KPICard(kpi_row, tr("web_requests"), "0", T["info"], "")
        self._kpi_requests.pack(side="left", expand=True, fill="both", padx=5)
        self._kpi_uptime = KPICard(kpi_row, tr("web_uptime"), "0s", T["accent_orange"], "")
        self._kpi_uptime.pack(side="left", expand=True, fill="both", padx=5)

        # Server Controls
        controls = ctk.CTkFrame(scroll, fg_color=T["bg_panel"], corner_radius=12)
        controls.pack(fill="x", padx=20, pady=(0, 12))
        section_label(controls, tr("web_settings"), "")
        btn_row = ctk.CTkFrame(controls, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 12))
        self._btn_start = ctk.CTkButton(btn_row, text=tr("web_start"), width=140, fg_color=T["safe"],
                                        text_color=T["bg_deep"], font=FONT_SMALL, corner_radius=DEFAULT_CORNER,
                                        command=self._start_server)
        self._btn_start.pack(side="left", padx=4)
        self._btn_stop = ctk.CTkButton(btn_row, text=tr("web_stop"), width=140, fg_color=T["danger"],
                                       text_color=T["text_primary"], font=FONT_SMALL, corner_radius=DEFAULT_CORNER,
                                       command=self._stop_server)
        self._btn_stop.pack(side="left", padx=4)
        self._btn_restart = ctk.CTkButton(btn_row, text=tr("web_restart"), width=140, fg_color=T["accent"],
                                          text_color=T["bg_deep"], font=FONT_SMALL, corner_radius=DEFAULT_CORNER,
                                          command=self._restart_server)
        self._btn_restart.pack(side="left", padx=4)

        # Settings
        settings = ctk.CTkFrame(controls, fg_color="transparent")
        settings.pack(fill="x", padx=16, pady=(0, 10))
        ctk.CTkLabel(settings, text=tr("web_port")+":", font=FONT_SMALL, text_color=T["text_primary"]).pack(side="left", padx=(0, 8))
        self._port_entry = ctk.CTkEntry(settings, width=100, fg_color=T["bg_card"],
                                       border_color=T["border"], text_color=T["text_primary"], font=FONT_MONO, corner_radius=8)
        self._port_entry.pack(side="left", padx=(0, 16))
        self._port_entry.insert(0, str(CFG.get("web_port", 5000)))
        self._autostart_var = ctk.BooleanVar(value=CFG.get("web_autostart", False))
        self._log_requests_var = ctk.BooleanVar(value=CFG.get("web_log_requests", False))
        ctk.CTkSwitch(settings, text=tr("web_autostart"), variable=self._autostart_var,
                     font=FONT_SMALL, fg_color=T["bg_card"], progress_color=T["accent"],
                     command=self._save_settings).pack(side="left", padx=8)
        ctk.CTkSwitch(settings, text=tr("web_log_requests"), variable=self._log_requests_var,
                     font=FONT_SMALL, fg_color=T["bg_card"], progress_color=T["accent"],
                     command=self._save_settings).pack(side="left", padx=8)
        ctk.CTkButton(settings, text=tr("save"), width=100, fg_color=T["accent"],
                     text_color=T["bg_deep"], font=FONT_SMALL, command=self._save_settings).pack(side="left", padx=8)
        ctk.CTkButton(settings, text=tr("web_open_config"), width=160, fg_color=T["bg_card"],
                     text_color=T["text_dim"], font=FONT_SMALL, command=self._open_config).pack(side="left", padx=8)

        # Server Info
        info_panel = ctk.CTkFrame(scroll, fg_color=T["bg_panel"], corner_radius=12)
        info_panel.pack(fill="x", padx=20, pady=(0, 20))
        section_label(info_panel, tr("web_server_info"), "")
        self._info_box = ctk.CTkTextbox(info_panel, height=120, fg_color=T["bg_card"],
                                       text_color=T["text_primary"], font=FONT_MONO)
        self._info_box.pack(fill="x", padx=16, pady=(0, 16))
        self._refresh_info()

    def _start_server(self):
        if not self.app_ref:
            return
        self.app_ref._start_flask_api()
        self._log_message("Web server started")

    def _stop_server(self):
        if not self.app_ref:
            return
        self.app_ref._stop_flask_api()
        self._log_message("Web server stopped")

    def _restart_server(self):
        if not self.app_ref:
            return
        self.app_ref._restart_flask_api()
        self._log_message("Web server restarting...")

    def _save_settings(self):
        port_str = self._port_entry.get()
        try:
            port = int(port_str)
            CFG["web_port"] = port
            CFG["web_autostart"] = self._autostart_var.get()
            CFG["web_log_requests"] = self._log_requests_var.get()
            self._kpi_port.set(str(port))
            # Apply dynamically (do not persist to disk until Save All)
            self._log_message("Settings applied (not saved to disk). Use Save All to persist.")
        except Exception as e:
            self._log_message(f"Error saving settings: {e}")

    def _refresh_info(self):
        import sys
        info_text = []
        info_text.append(f"Python: {sys.version.split()[0]}")
        try:
            from importlib.metadata import version
            flask_version = version("flask")
        except Exception:
            flask_version = "unknown"
        info_text.append(f"Flask: {flask_version}")
        port = int(CFG.get("web_port", 5000))
        info_text.append(f"Port: {port}")
        info_text.append(f"Autostart: {('Yes' if CFG.get('web_autostart', False) else 'No')}")
        info_text.append(f"Log requests: {('Yes' if CFG.get('web_log_requests', False) else 'No')}")
        self._info_box.configure(state="normal")
        self._info_box.delete("0.0", "end")
        self._info_box.insert("end", "\n".join([f" {line}" for line in info_text]))
        self._info_box.configure(state="disabled")

    def _log_message(self, msg):
        self._info_box.configure(state="normal")
        self._info_box.insert("end", f"\n [{datetime.now().strftime('%H:%M:%S')}] {msg}")
        self._info_box.configure(state="disabled")

    def _open_config(self):
        import subprocess
        import sys
        import os
        config_path = ROOT_DIR / "sentinel_config.json"
        try:
            if sys.platform == "win32":
                os.startfile(config_path)
            elif sys.platform == "darwin":
                subprocess.call(["open", str(config_path)])
            else:
                subprocess.call(["xdg-open", str(config_path)])
        except Exception as e:
            self._log_message(f"Error opening config: {e}")

    def _refresh(self):
        try:
            from utils.network import get_connection_urls
            port = int(CFG.get("web_port", 5000))
            urls = get_connection_urls(port)
            lines = [f" {u['label']}: {u['url']}" for u in urls] or [" Wi-Fi IP не найден"]
            try:
                self._url_box.configure(state="normal")
                self._url_box.delete("0.0", "end")
                self._url_box.insert("end", "\n".join(lines))
                self._url_box.configure(state="disabled")
            except Exception: pass
            self._primary = urls[0]["url"] if urls else ""

            # Update KPIs from app_ref
            if self.app_ref:
                try:
                    # Status
                    if self.app_ref._flask_running:
                        self._kpi_status.set(tr("active_status"))
                        self._kpi_status.set_color(T["safe"])
                    else:
                        self._kpi_status.set(tr("blocked_status"))
                        self._kpi_status.set_color(T["danger"])
                    # Requests
                    self._kpi_requests.set(str(self.app_ref._flask_request_count))
                    # Uptime
                    if self.app_ref._flask_running and self.app_ref._flask_start_time:
                        delta = datetime.now() - self.app_ref._flask_start_time
                        total_secs = int(delta.total_seconds())
                        hours, remainder = divmod(total_secs, 3600)
                        mins, secs = divmod(remainder, 60)
                        if hours > 0:
                            uptime_str = f"{hours}h {mins}m {secs}s"
                        elif mins > 0:
                            uptime_str = f"{mins}m {secs}s"
                        else:
                            uptime_str = f"{secs}s"
                        self._kpi_uptime.set(uptime_str)
                    else:
                        self._kpi_uptime.set("0s")
                except Exception: pass
        except Exception as e:
            logging.error(f"WebAccessPage refresh error: {e}")

    def _copy(self):
        try:
            if getattr(self, "_primary", None):
                self.clipboard_clear()
                self.clipboard_append(self._primary)
        except Exception as e:
            logging.error(f"WebAccessPage copy error: {e}")

    def _open(self):
        try:
            import webbrowser
            if getattr(self, "_primary", None):
                webbrowser.open(self._primary)
        except Exception as e:
            logging.error(f"WebAccessPage open error: {e}")

    def _tick(self):
        import logging
        logging.debug(f"[DBG-04] WebAccessPage._tick(): refresh starting")
        try:
            self._refresh()
        except Exception as e:
            logging.error(f"WebAccessPage tick error: {e}")
        self.after(2000, self._tick)

class TopologyPage(ctk.CTkFrame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine; self._build(); self._tick()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        top.pack(fill="both",expand=True,padx=20,pady=(20,8))
        section_label(top, f" {tr('network_topology')}", "ARP-based host discovery")
        self.fig = plt.Figure(figsize=(10,5.5), facecolor=T["mpl_bg"])
        self.ax  = self.fig.add_subplot(111)
        self.ax.set_facecolor(T["mpl_bg"]); self.ax.axis("off")
        make_canvas(top, self.fig)
        bot = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=12)
        bot.pack(fill="x",padx=20,pady=(0,20))
        section_label(bot, f" {tr('discovered_hosts')}", tr("from_arp_table"))
        ctl_row = ctk.CTkFrame(bot, fg_color="transparent")
        ctl_row.pack(fill="x", padx=8, pady=(0,6))
        ctk.CTkButton(ctl_row, text=tr("probe_hosts"), width=140, height=30,
                      fg_color=T["accent"], text_color=T["bg_deep"],
                      command=self._probe_hosts).pack(side="left", padx=(0,8))
        ctk.CTkButton(ctl_row, text=tr("export"), width=120, height=30,
                      fg_color=T["bg_card"], text_color=T["text_dim"],
                      command=self._export_hosts).pack(side="left")

        cols = ("ip","mac","hostname","vendor","top_app","last_seen","status")
        self.htree = ttk.Treeview(bot, columns=cols, show="headings",
                                   style="Sentinel.Treeview", height=5)
        for col,w in zip(cols,[120,150,170,140,160,110,100]):
            col_key = "col_"+col if col != "ip" else "ip_control"
            self.htree.heading(col,text=tr(col_key)); self.htree.column(col,width=w,anchor="w")
        self.htree.pack(fill="x",padx=8,pady=(0,10))
        self._host_cache = {}
        self._last_seen = {}
        try:
            self._apps_by_ip = collections.defaultdict(lambda: collections.Counter())
        except Exception:
            self._apps_by_ip = {}
        try:
            self._executor = ThreadPoolExecutor(max_workers=4)
        except Exception:
            self._executor = None

    def _tick(self):
        try: self._draw_topology()
        except Exception: pass
        self.after(5000,self._tick)

    def _draw_topology(self):
        try:
            draw_topology(self.ax, dict(self.engine.arp_table), set(self.engine.blocked_ips), list(self.engine.alerts))
            self.fig.canvas.draw_idle()
        except Exception:
            import math
            self.ax.clear(); self.ax.set_facecolor(T["mpl_bg"]); self.ax.axis("off")
            arp = dict(self.engine.arp_table); ips = list(arp.keys())[:24]
            if not ips:
                self.ax.text(0.5,0.5, tr("waiting_for_arp"), ha="center",va="center",
                             color=T["text_dim"],fontsize=14,transform=self.ax.transAxes)
                self.fig.canvas.draw_idle(); return
            n = len(ips); cx,cy,r = 0.5,0.5,0.38
            self.ax.scatter([cx],[cy],s=500,color=T["accent"],zorder=5,marker="D")
            self.ax.text(cx,cy-0.08,"GATEWAY",ha="center",color=T["accent"],
                         fontsize=9,fontweight="bold")
            for i,ip in enumerate(ips):
                angle = 2*math.pi*i/n; x = cx+r*math.cos(angle); y = cy+r*math.sin(angle)
                c = T["danger"] if ip in self.engine.blocked_ips else T["safe"]
                self.ax.plot([cx,x],[cy,y],color=T["border"],lw=0.8,zorder=1)
                self.ax.scatter([x],[y],s=220,color=c,zorder=4,alpha=0.9)
                self.ax.text(x,y-0.06,ip,ha="center",color=c,fontsize=7)
            self.fig.canvas.draw_idle()
        try:
            for i in self.htree.get_children():
                try: self.htree.delete(i)
                except Exception: pass
        except Exception:
            pass
        now = datetime.now()
        try:
            if self.engine.lock.acquire(timeout=0.05):
                try:
                    arp_items = list(self.engine.arp_table.items())[:240]
                finally:
                    self.engine.lock.release()
            else:
                arp_items = []
        except Exception:
            arp_items = []
        for ip, mac in arp_items:
            self._last_seen[ip] = now
            if ip not in self._host_cache:
                if self._executor:
                    self._executor.submit(self._resolve_host, ip)
                else:
                    try: self._host_cache[ip] = socket.gethostbyaddr(ip)[0]
                    except Exception: self._host_cache[ip] = ""
            try:
                from core.threat_engine import load_oui, lookup_vendor
                try: load_oui()
                except Exception: pass
                vendor = lookup_vendor(mac)
            except Exception:
                vendor = "Unknown"
            hostname = self._host_cache.get(ip, "")
            top_app = ""
            try:
                cnt = self._apps_by_ip.get(ip)
                if cnt: top_app = cnt.most_common(1)[0][0]
            except Exception: top_app = ""
            last_seen = self._last_seen.get(ip).strftime("%H:%M:%S") if self._last_seen.get(ip) else ""
            status = tr("blocked_status") if ip in self.engine.blocked_ips else tr("active_status")
            self.htree.insert("","end",values=(ip,mac,hostname,vendor,top_app,last_seen,status))

    def record_host_activity(self, ip, app):
        try:
            if not ip: return
            if isinstance(self._apps_by_ip, dict):
                self._apps_by_ip.setdefault(ip, {})
                cnt = self._apps_by_ip[ip]
                cnt[app] = cnt.get(app, 0) + 1
            else:
                self._apps_by_ip[ip].update([app])
            self._last_seen[ip] = datetime.now()
            def _update():
                try:
                    for iid in self.htree.get_children():
                        vals = self.htree.item(iid).get('values')
                        if vals and vals[0] == ip:
                            top_app = ""
                            try:
                                cnt = self._apps_by_ip.get(ip)
                                if cnt:
                                    if hasattr(cnt, 'most_common'):
                                        top_app = cnt.most_common(1)[0][0]
                                    else:
                                        top_app = max(cnt.items(), key=lambda x: x[1])[0]
                            except Exception: top_app = ""
                            vals[4] = top_app
                            vals[5] = self._last_seen[ip].strftime("%H:%M:%S")
                            self.htree.item(iid, values=vals); break
                except Exception: pass
            try: self.after(0, _update)
            except Exception: pass
        except Exception: pass

    def _resolve_host(self, ip):
        try: hn = socket.gethostbyaddr(ip)[0]
        except Exception: hn = ""
        self._host_cache[ip] = hn
        try:
            def _update():
                try:
                    for iid in self.htree.get_children():
                        vals = self.htree.item(iid).get('values')
                        if vals and vals[0] == ip:
                            vals[2] = hn; self.htree.item(iid, values=vals); break
                except Exception:
                    pass
            try: self.after(0, _update)
            except Exception: pass
        except Exception: pass

    def _probe_hosts(self):
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Probe","Scapy not available. Enable scapy for active probing.")
            return
        try:
            def _run():
                try:
                    iface = self.master.adapter if hasattr(self.master, 'adapter') else None
                    addrs = psutil.net_if_addrs().get(iface, []) if iface else []
                    ipv4 = None
                    for a in addrs:
                        if getattr(a, 'family', None) == socket.AF_INET:
                            ipv4 = a.address; break
                    targets = []
                    if ipv4:
                        base = '.'.join(ipv4.split('.')[:3])
                        targets = [f"{base}.{i}" for i in range(1,255)]
                    else:
                        targets = [f"192.168.1.{i}" for i in range(1,255)]
                    import scapy.all as scapy
                    ans,unans = scapy.arping(targets, timeout=2, verbose=False)
                    if self.engine.lock.acquire(timeout=0.2):
                        try:
                            for s,r in ans:
                                ip = r.psrc; mac = r.hwsrc
                                self.engine.arp_table[ip] = mac
                        finally:
                            self.engine.lock.release()
                    else:
                        logging.warning("_probe_hosts: engine.lock busy, ARP results skipped")
                except Exception:
                    logging.exception("Active probe failed")
                finally:
                    try: self.after(0, self._draw_topology)
                    except Exception: pass
            threading.Thread(target=_run, daemon=True).start()
        except Exception: pass

    def _export_hosts(self):
        try:
            path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV','*.csv')])
            if not path: return
            with open(path, 'w', encoding='utf-8') as f:
                f.write('ip,mac,hostname,vendor,last_seen,status\n')
                try:
                    for iid in self.htree.get_children():
                        try:
                            vals = self.htree.item(iid).get('values')
                            if not vals: continue
                            row = [str(v).replace(',', ' ') for v in vals]
                            f.write(','.join(row) + '\n')
                        except Exception:
                            pass
                except Exception:
                    pass
            messagebox.showinfo(tr('export'), 'Hosts exported to: ' + path)
        except Exception:
            logging.exception('Export hosts failed')

class LogsPage(ctk.CTkFrame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine
        self._log_path = LOG_DIR / f"sentinel_{datetime.now().strftime('%Y%m%d')}.log"
        self._file_q: queue.Queue = queue.Queue(maxsize=500)
        self._writer_thread = threading.Thread(
            target=self._file_writer_loop,
            daemon=True,
            name="LogFileWriter",
        )
        self._writer_thread.start()
        self._build()

    def _file_writer_loop(self) -> None:
        while True:
            try:
                line = self._file_q.get(timeout=2)
                if line is None:
                    break
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except queue.Empty:
                continue
            except Exception:
                pass

    def _build(self):
        tb = ctk.CTkFrame(self, fg_color=T["bg_panel"], corner_radius=10)
        tb.pack(fill="x",padx=20,pady=(20,8))
        ctk.CTkLabel(tb, text=tr('logs'), font=FONT_HEADER,
                     text_color=T["accent"]).pack(side="left",padx=14,pady=10)
        ctk.CTkButton(tb, text=tr('clear'), width=80, font=FONT_SMALL,
                      fg_color=T["bg_card"], text_color=T["text_dim"],
                      command=self._clear).pack(side="right",padx=6)
        ctk.CTkButton(tb, text=tr('export'), width=90, font=FONT_SMALL,
                      fg_color=T["accent"], text_color=T["bg_deep"],
                      command=self._export).pack(side="right",padx=6)
        self.box = ctk.CTkTextbox(self, fg_color=T["bg_panel"],
                                   text_color=T["safe"], font=("Courier New",10))
        self.box.pack(fill="both",expand=True,padx=20,pady=(0,20))
        self.box.configure(state="disabled")

    def append(self, msg: str, level: str = "INFO") -> None:
        self.box.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.box.insert("end", f"[{ts}] [{level:8s}]  {msg}\n")
        self.box.see("end")
        self.box.configure(state="disabled")

        if CFG.get("log_to_file"):
            line = f"[{datetime.now()}] [{level}] {msg}\n"
            try:
                self._file_q.put_nowait(line)
            except queue.Full:
                pass

    def _clear(self):
        self.box.configure(state="normal"); self.box.delete("0.0","end")
        self.box.configure(state="disabled")

    def _export(self):
        messagebox.showinfo(tr("export"), f"Logs: {self._log_path.absolute()}\n"
                             f"AI dialogs: {LOG_DIR.absolute()}")

class SettingsPage(ctk.CTkFrame):
    def __init__(self, master, engine, app_ref, current_user=None, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.engine = engine; self.app_ref = app_ref
        self.current_user = current_user or ("guest","user")
        self._build()

    def _build(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=20)
        u, role = self.current_user; is_admin = (role == "admin")

        self._section(scroll, tr('current_session'))
        info = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=10)
        info.pack(fill="x",padx=24,pady=(0,8))
        ctk.CTkLabel(info, text=u.upper(),
                     font=FONT_HEADER, text_color=T["accent"]).pack(side="left",padx=16,pady=12)
        ctk.CTkLabel(info, text=f"{tr('role')}: {tr(role).upper()}", font=FONT_SMALL,
                     text_color=T["text_dim"]).pack(side="right",padx=16)

        self._section(scroll, tr('capture_mode'))
        mode_card = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=12)
        mode_card.pack(fill="x",padx=24,pady=(0,12))
        ind_row = ctk.CTkFrame(mode_card, fg_color="transparent")
        ind_row.pack(fill="x",padx=16,pady=(14,4))
        self._mode_indicator = ctk.CTkLabel(ind_row, text="", font=(FONT_FAMILY_MONO,12,"bold"),
            text_color=T["bg_deep"], fg_color=T["warn"], corner_radius=8, width=270, height=28)
        self._mode_indicator.pack(side="left", padx=(0,12))
        self._demo_var = tk.BooleanVar(value=CFG.get("demo_mode",True))
        self._mode_switch = ctk.CTkSwitch(ind_row, text="", variable=self._demo_var,
            font=FONT_SMALL, text_color=T["text_primary"], progress_color=T["warn"],
            command=self._on_mode_toggle)
        self._mode_switch.pack(side="left")
        self._mode_desc = ctk.CTkLabel(mode_card, text="", font=FONT_SMALL,
            text_color=T["text_dim"], wraplength=520, justify="left")
        self._mode_desc.pack(anchor="w",padx=16,pady=(0,12))
        self._update_mode_ui()

        self._section(scroll, tr('ai_assistant'))
        ai_card = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=12)
        ai_card.pack(fill="x",padx=24,pady=(0,12))
        self._ai_fallback = tk.BooleanVar(value=CFG.get("ai_auto_fallback",True))
        self._ai_log      = tk.BooleanVar(value=CFG.get("ai_log_dialogs",True))
        ctk.CTkSwitch(ai_card, text=tr("auto_fallback"),
                      variable=self._ai_fallback, font=FONT_BODY,
                      text_color=T["text_primary"],
                      progress_color=T["accent"]).pack(anchor="w",padx=16,pady=(8,4))
        ctk.CTkSwitch(ai_card, text=tr("log_ai_dialogs"),
                      variable=self._ai_log, font=FONT_BODY,
                      text_color=T["text_primary"],
                      progress_color=T["accent"]).pack(anchor="w",padx=16,pady=(0,12))
        # AI provider API keys
        r = ctk.CTkFrame(ai_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=(4,4))
        ctk.CTkLabel(r, text="Gemini API Key", font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._ai_gemini_var = tk.StringVar(value=str(CFG.get("gemini_api_key", "")))
        self._ai_gemini = ctk.CTkEntry(r, width=420, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, show="•", textvariable=self._ai_gemini_var)
        self._ai_gemini.pack(side="left", padx=8)

        r2 = ctk.CTkFrame(ai_card, fg_color="transparent"); r2.pack(fill="x", padx=16, pady=(4,4))
        ctk.CTkLabel(r2, text="OpenAI API Key", font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._ai_openai_var = tk.StringVar(value=str(CFG.get("openai_api_key", "")))
        self._ai_openai = ctk.CTkEntry(r2, width=420, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, show="•", textvariable=self._ai_openai_var)
        self._ai_openai.pack(side="left", padx=8)

        r3 = ctk.CTkFrame(ai_card, fg_color="transparent"); r3.pack(fill="x", padx=16, pady=(4,8))
        ctk.CTkLabel(r3, text="Claude / Anthropic Key", font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._ai_claude_var = tk.StringVar(value=str(CFG.get("ai_api_key", "")))
        self._ai_claude = ctk.CTkEntry(r3, width=420, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, show="•", textvariable=self._ai_claude_var)
        self._ai_claude.pack(side="left", padx=8)
        self._section(scroll, tr('telegram_bot'))
        tg_card = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=12)
        tg_card.pack(fill="x", padx=24, pady=(0, 12))

        tg_r1 = ctk.CTkFrame(tg_card, fg_color="transparent")
        tg_r1.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(tg_r1, text=tr("bot_token"), font=FONT_SMALL,
                     text_color=T["text_dim"], width=120).pack(side="left")
        self._tg_token = ctk.CTkEntry(tg_r1, width=340, font=FONT_MONO,
                                       fg_color=T["bg_card"], border_color=T["border"],
                                       text_color=T["text_primary"], corner_radius=8,
                                       placeholder_text=tr("bot_token_placeholder"),
                                       show="•")
        self._tg_token.insert(0, CFG.get("tg_token", ""))
        self._tg_token.pack(side="left", padx=8)

        tg_r2 = ctk.CTkFrame(tg_card, fg_color="transparent")
        tg_r2.pack(fill="x", padx=16, pady=(4, 8))
        ctk.CTkLabel(tg_r2, text=tr("chat_id"), font=FONT_SMALL,
                     text_color=T["text_dim"], width=120).pack(side="left")
        self._tg_chat = ctk.CTkEntry(tg_r2, width=200, font=FONT_MONO,
                                      fg_color=T["bg_card"], border_color=T["border"],
                                      text_color=T["text_primary"], corner_radius=8,
                                      placeholder_text=tr("chat_id_placeholder"))
        self._tg_chat.insert(0, CFG.get("tg_chat_id", ""))
        self._tg_chat.pack(side="left", padx=8)

        tg_hint = ctk.CTkLabel(tg_card, text=tr("tg_hint"),
                               font=FONT_SMALL, text_color=T["text_dim"], wraplength=500, justify="left")
        tg_hint.pack(anchor="w", padx=16, pady=(0, 8))

        btn_row = ctk.CTkFrame(tg_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkButton(btn_row, text=tr("get_chat_id"), width=160,
                      fg_color=T["bg_hover"], text_color=T["accent"], font=FONT_SMALL,
                      command=self._tg_get_chat_id).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text=tr("test_connection"), width=180,
                      fg_color=T["bg_hover"], text_color=T["accent"], font=FONT_SMALL,
                      command=self._tg_test).pack(side="left", padx=(0, 8))

        self._tg_status = ctk.CTkLabel(tg_card, text="", font=FONT_SMALL,
                                        text_color=T["text_dim"])
        self._tg_status.pack(side="left", padx=8)

        self._section(scroll, tr('network_interface'))
        if is_admin:
            adapters = list(psutil.net_if_addrs().items())
            self._adapter_var = tk.StringVar(value=CFG.get("adapter",""))
            for name, addrs in adapters:
                ips = [a.address for a in addrs if a.family==socket.AF_INET]
                ctk.CTkRadioButton(scroll, text=f"{name}  ({', '.join(ips) or 'no IP'})",
                                   variable=self._adapter_var, value=name,
                                   font=FONT_BODY, text_color=T["text_primary"],
                                   fg_color=T["accent"]).pack(anchor="w",padx=24,pady=3)
            ctk.CTkButton(scroll, text=tr('apply_and_restart'), width=240,
                          fg_color=T["accent"], text_color=T["bg_deep"], font=FONT_SMALL,
                          command=self._apply_adapter).pack(anchor="w",padx=24,pady=(10,20))
        else:
            ctk.CTkLabel(scroll, text=tr("adapter_admin_required"),
                     font=FONT_SMALL, text_color=T["warn"]).pack(anchor="w",padx=24,pady=8)

        self._section(scroll, tr('appearance'))
        row = ctk.CTkFrame(scroll, fg_color="transparent"); row.pack(fill="x",padx=24,pady=6)
        ctk.CTkLabel(row, text=tr("theme"), font=FONT_SMALL, text_color=T["text_dim"],
                     width=120).pack(side="left")
        self._theme_var = tk.StringVar(value=CFG["theme"])
        for t_val in ("dark","light"):
            ctk.CTkRadioButton(row,text=t_val.capitalize(),variable=self._theme_var,
                               value=t_val,font=FONT_BODY,text_color=T["text_primary"],
                               fg_color=T["accent"]).pack(side="left",padx=12)
        row2 = ctk.CTkFrame(scroll, fg_color="transparent"); row2.pack(fill="x",padx=24,pady=6)
        ctk.CTkLabel(row2, text=tr("accent"), font=FONT_SMALL, text_color=T["text_dim"],
                     width=120).pack(side="left")
        self._accent_var = tk.StringVar(value=CFG["accent"])
        for ac in ("cyan","green","orange","purple"):
            ctk.CTkRadioButton(row2,text=ac.capitalize(),variable=self._accent_var,
                               value=ac,font=FONT_BODY,text_color=T["text_primary"],
                               fg_color=ACCENT_MAP[ac]).pack(side="left",padx=12)
        ctk.CTkButton(scroll, text=tr("apply_theme"), width=240,
                      fg_color=T["bg_card"], text_color=T["text_dim"], font=FONT_SMALL,
                      command=self._apply_theme).pack(anchor="w",padx=24,pady=(10,20))

        self._section(scroll, tr('language'))
        lang_row = ctk.CTkFrame(scroll, fg_color="transparent")
        lang_row.pack(fill="x",padx=24,pady=(6,8))
        ctk.CTkLabel(lang_row, text=tr("language")+":", font=FONT_SMALL, text_color=T["text_dim"], width=120).pack(side="left")
        self._lang_var = tk.StringVar(value=CFG.get("language","en"))
        for code, label in [("en","English"),("ru","Русский"),("kk","Қазақша")]:
            ctk.CTkRadioButton(lang_row, text=label, variable=self._lang_var, value=code,
                               font=FONT_BODY, text_color=T["text_primary"], fg_color=T["accent"]).pack(side="left", padx=8)
        ctk.CTkButton(scroll, text=tr("save"), width=160,
                      fg_color=T["accent"], text_color=T["bg_deep"], font=FONT_SMALL,
                      command=self._apply_language).pack(anchor="w",padx=24,pady=(6,12))

        self._section(scroll, tr('detection_thresholds'))
        if is_admin:
            sliders = [
                (tr("pps_thresh_label"),       "pps_thresh",    50,1000,10),
                (tr("syn_thresh_label"),       "syn_thresh",    20,300,1),
                (tr("scan_thresh_label"),       "scan_thresh",    5, 50,1),
                (tr("icmp_thresh_label"),      "icmp_thresh",   10,200,1),
                (tr("data_exfil_label"),       "data_exfil_kb",  2, 64,1),
            ]
            self._sliders = {}
            for label,key,mn,mx,step in sliders:
                f = ctk.CTkFrame(scroll, fg_color="transparent"); f.pack(fill="x",padx=24,pady=4)
                ctk.CTkLabel(f,text=label,font=FONT_SMALL,text_color=T["text_dim"],
                             width=300).pack(side="left")
                lbl = ctk.CTkLabel(f,text=str(CFG.get(key, '')),font=FONT_BODY,
                                    text_color=T["text_primary"],width=50)
                lbl.pack(side="right")
                sl = ctk.CTkSlider(f,from_=mn,to=mx,number_of_steps=int((mx-mn)/step),
                                   command=lambda v,l=lbl,k=key: self._sl_update(v,l,k))
                try: sl.set(CFG.get(key, mn))
                except Exception: sl.set(mn)
                sl.pack(side="right",padx=10); self._sliders[key] = sl
        else:
            ctk.CTkLabel(scroll, text=tr("threshold_admin_required"),
                     font=FONT_SMALL, text_color=T["warn"]).pack(anchor="w",padx=24,pady=8)

        if is_admin:
            self._section(scroll, tr('user_management'))
            cols = ("username","role","created")
            utree = ttk.Treeview(scroll, columns=cols, show="headings",
                                  style="Sentinel.Treeview", height=4)
            for col,w in zip(cols,[140,80,200]):
                utree.heading(col,text=tr("col_"+col)); utree.column(col,width=w,anchor="w")
            for uname,udata in USERS.items():
                utree.insert("","end",values=(uname,tr(udata.get("role","operator")),
                                               udata.get("created","")))
            utree.pack(fill="x",padx=24,pady=(0,8))

        self._section(scroll, tr('behaviour'))
        self._auto_block = tk.BooleanVar(value=CFG.get("auto_block",False))
        self._log_file   = tk.BooleanVar(value=CFG.get("log_to_file",True))
        ctk.CTkSwitch(scroll, text=tr("auto_block"),
                      variable=self._auto_block, font=FONT_BODY,
                      text_color=T["text_primary"],
                      progress_color=T["accent"]).pack(anchor="w",padx=24,pady=6)
        ctk.CTkSwitch(scroll, text=tr("write_logs"), variable=self._log_file,
                      font=FONT_BODY, text_color=T["text_primary"],
                      progress_color=T["accent"]).pack(anchor="w",padx=24,pady=6)
        row3 = ctk.CTkFrame(scroll, fg_color="transparent"); row3.pack(fill="x",padx=24,pady=4)
        ctk.CTkLabel(row3, text=tr("max_table_rows"), font=FONT_SMALL,
                     text_color=T["text_dim"], width=200).pack(side="left")
        self._max_rows = ctk.CTkEntry(row3, width=80, font=FONT_BODY,
                                       fg_color=T["bg_card"], border_color=T["border"],
                                       text_color=T["text_primary"], corner_radius=8)
        self._max_rows.insert(0,str(CFG.get("max_table_rows",200)))
        self._max_rows.pack(side="left",padx=10)

        self._section(scroll, tr('notifications'))
        notif_card = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=12)
        notif_card.pack(fill="x", padx=24, pady=(0,12))
        
        # Email Settings
        ctk.CTkLabel(notif_card, text=tr('email'), font=FONT_SMALL,
                     text_color=T["accent"], fg_color=T["bg_deep"], corner_radius=8, width=150).pack(anchor="w", padx=16, pady=(8,4))
        for label, key, placeholder in [
            (tr('email_server'), "email_server", "smtp.gmail.com"),
            (tr('email_port'), "email_port", "587"),
            (tr('email_recipient'), "email_recipient", "user@example.com"),
        ]:
            r = ctk.CTkFrame(notif_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(r, text=label, font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
            entry = ctk.CTkEntry(r, width=300, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, placeholder_text=placeholder)
            entry.insert(0, str(CFG.get(key, "")))
            entry.pack(side="left", padx=8)
            setattr(self, f"_notif_{key}", entry)
        # Email user and password
        r = ctk.CTkFrame(notif_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=2)
        ctk.CTkLabel(r, text=tr('email_user'), font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._notif_email_user = ctk.CTkEntry(r, width=300, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, placeholder_text="user@gmail.com")
        self._notif_email_user.insert(0, str(CFG.get("email_user", "")))
        self._notif_email_user.pack(side="left", padx=8)
        r = ctk.CTkFrame(notif_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=(2,8))
        ctk.CTkLabel(r, text=tr('email_password'), font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._notif_email_password = ctk.CTkEntry(r, width=300, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, placeholder_text="app password", show="•")
        self._notif_email_password.insert(0, str(CFG.get("email_password", "")))
        self._notif_email_password.pack(side="left", padx=8)

        # Discord and Slack
        ctk.CTkLabel(notif_card, text=tr('discord'), font=FONT_SMALL,
                     text_color=T["accent"], fg_color=T["bg_deep"], corner_radius=8, width=150).pack(anchor="w", padx=16, pady=(8,4))
        r = ctk.CTkFrame(notif_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=2)
        ctk.CTkLabel(r, text=tr('discord_webhook'), font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._notif_discord_webhook = ctk.CTkEntry(r, width=400, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, placeholder_text="https://discord.com/api/webhooks/...")
        self._notif_discord_webhook.insert(0, str(CFG.get("discord_webhook", "")))
        self._notif_discord_webhook.pack(side="left", padx=8)
        ctk.CTkLabel(notif_card, text=tr('slack'), font=FONT_SMALL,
                     text_color=T["accent"], fg_color=T["bg_deep"], corner_radius=8, width=150).pack(anchor="w", padx=16, pady=(8,4))
        r = ctk.CTkFrame(notif_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=(2,8))
        ctk.CTkLabel(r, text=tr('slack_webhook'), font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
        self._notif_slack_webhook = ctk.CTkEntry(r, width=400, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, placeholder_text="https://hooks.slack.com/services/...")
        self._notif_slack_webhook.insert(0, str(CFG.get("slack_webhook", "")))
        self._notif_slack_webhook.pack(side="left", padx=8)

        # System Toasts
        self._notif_system_toasts = tk.BooleanVar(value=CFG.get("system_toasts", False))
        ctk.CTkSwitch(notif_card, text=tr('system_toasts'), variable=self._notif_system_toasts,
                      font=FONT_BODY, text_color=T["text_primary"], progress_color=T["accent"]).pack(anchor="w", padx=16, pady=(0,12))

        self._section(scroll, tr('integrations'))
        int_card = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=12)
        int_card.pack(fill="x", padx=24, pady=(0,12))
        for label, key, placeholder in [
            (tr('virustotal_api'), "virustotal_api", "your_api_key_here"),
            (tr('abuseipdb_api'), "abuseipdb_api", "your_api_key_here"),
        ]:
            r = ctk.CTkFrame(int_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=8)
            ctk.CTkLabel(r, text=label, font=FONT_SMALL, text_color=T["text_dim"], width=150).pack(side="left")
            entry = ctk.CTkEntry(r, width=400, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8, placeholder_text=placeholder, show="•")
            entry.insert(0, str(CFG.get(key, "")))
            entry.pack(side="left", padx=8)
            setattr(self, f"_int_{key}", entry)

        self._section(scroll, tr('export_config'))
        cfg_card = ctk.CTkFrame(scroll, fg_color=T["bg_card"], corner_radius=12)
        cfg_card.pack(fill="x", padx=24, pady=(0,12))
        r = ctk.CTkFrame(cfg_card, fg_color="transparent"); r.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(r, text=tr('export_config'), width=140, fg_color=T["accent"], text_color=T["bg_deep"],
                      font=FONT_SMALL, corner_radius=DEFAULT_CORNER, command=self._export_cfg).pack(side="left", padx=4)
        ctk.CTkButton(r, text=tr('import_config'), width=140, fg_color=T["safe"], text_color=T["bg_deep"],
                      font=FONT_SMALL, corner_radius=DEFAULT_CORNER, command=self._import_cfg).pack(side="left", padx=4)
        self._auto_backup = tk.BooleanVar(value=CFG.get("auto_backup", False))
        ctk.CTkSwitch(r, text=tr('auto_backup'), variable=self._auto_backup,
                      font=FONT_BODY, text_color=T["text_primary"], progress_color=T["accent"]).pack(side="left", padx=12)
        ctk.CTkLabel(r, text=tr('backup_interval')+":", font=FONT_SMALL, text_color=T["text_dim"]).pack(side="left", padx=8)
        self._backup_interval = ctk.CTkEntry(r, width=80, font=FONT_MONO, fg_color=T["bg_card"], border_color=T["border"], text_color=T["text_primary"], corner_radius=8)
        self._backup_interval.insert(0, str(CFG.get("backup_interval", 24)))
        self._backup_interval.pack(side="left", padx=4)

        ctk.CTkButton(scroll, text=tr("save_all"), width=220,
                      fg_color=T["safe"], text_color=T["bg_deep"], font=FONT_HEADER,
                      command=self._save_all).pack(anchor="w",padx=24,pady=(20,10))
        self._status = ctk.CTkLabel(scroll, text="", font=FONT_SMALL, text_color=T["safe"])
        self._status.pack(anchor="w",padx=24)

    def _update_mode_ui(self):
        is_demo = self._demo_var.get()
        if is_demo:
            self._mode_indicator.configure(
                text=f"{tr('simulation_mode')}", fg_color=T["warn"], text_color=T["bg_deep"])
            self._mode_desc.configure(text=tr("demo_mode_desc"))
            self._mode_switch.configure(progress_color=T["warn"])
        else:
            self._mode_indicator.configure(
                text=f"{tr('live_mode')}", fg_color=T["safe"], text_color=T["bg_deep"])
            self._mode_desc.configure(text=tr("live_mode_desc"))
            self._mode_switch.configure(progress_color=T["safe"])

    def _on_mode_toggle(self):
        is_demo = self._demo_var.get()
        self._update_mode_ui(); CFG["demo_mode"] = is_demo
        self.app_ref.apply_mode(is_demo)
        self._status.configure(text=f" {'SIMULATION' if is_demo else 'LIVE CAPTURE'} mode.")
        try: self.app_ref.pages["dash"]._refresh_mode_banner()
        except Exception: pass

    def _section(self, parent, title):
        f = ctk.CTkFrame(parent, fg_color="transparent"); f.pack(fill="x",pady=(16,4))
        ctk.CTkLabel(f, text=title, font=FONT_HEADER, text_color=T["accent"]).pack(side="left")
        ctk.CTkFrame(parent, fg_color=T["border"], height=1).pack(fill="x",pady=(2,6))

    def _sl_update(self, val, lbl, key):
        ival = int(float(val)); lbl.configure(text=str(ival)); CFG[key] = ival

    def _apply_adapter(self):
        new = self._adapter_var.get()
        if new:
            if not self.app_ref._adapter_exists(new):
                messagebox.showwarning("Adapter not found", f"Adapter '{new}' is not available on this system.")
                return
            # Apply adapter dynamically in-memory; persist only on Save All
            CFG["adapter"] = new
            self.app_ref.restart_capture(new)
            self._status.configure(text=f"  Capture restarted on {new}")

    def _tg_test(self):
        token = self._tg_token.get().strip()
        chat_id = self._tg_chat.get().strip()
        print(f"[TG DEBUG] token={token[:20] if token else 'EMPTY'}..., chat_id={chat_id}")
        if not token or not chat_id:
            self._tg_status.configure(text=tr("tg_token_chat_id_empty"), text_color=T["warn"])
            print("[TG DEBUG] Token или chat_id пуст!")
            return
        self._tg_status.configure(text=tr("tg_sending"), text_color=T["text_dim"])
        def _send(token_val=token, chat_id_val=chat_id):
            try:
                import requests
                import json
                print(f"[TG DEBUG] Начало отправки. Token: {token_val[:20]}..., ChatID: {chat_id_val}")

                try:
                    chat_id_int = int(chat_id_val)
                except ValueError:
                    raise ValueError(f"Chat ID должен быть числом, получено: {chat_id_val}")

                payload = {
                    "chat_id": chat_id_int,
                    "text": " *SOC Sentinel* подключён!\nTelegram-бот активен.",
                    "parse_mode": "Markdown"
                }
                url = f"https://api.telegram.org/bot{token_val}/sendMessage"
                print(f"[TG DEBUG] URL: {url}")
                print(f"[TG DEBUG] Payload: {payload}")
                r = requests.post(url, json=payload, timeout=8)
                print(f"[TG DEBUG] Статус ответа: {r.status_code}")
                print(f"[TG DEBUG] Ответ: {r.text[:500]}")

                if r.status_code == 200:
                    print("[TG DEBUG]  Успешно!")
                    self.after(0, lambda: self._tg_status.configure(
                        text=tr("tg_sent"), text_color=T["safe"]))
                else:
                    try:
                        resp_json = r.json()
                        err = resp_json.get("description", str(resp_json))
                    except:
                        err = r.text
                    print(f"[TG DEBUG]  Ошибка: {err}")

                    if "chat not found" in err.lower():
                        hint = "Отправьте /start боту, затем напишите текст сообщения"
                        self.after(0, lambda h=hint: self._tg_status.configure(
                            text=f" Chat not found. {h}", text_color=T["danger"]))
                    else:
                        self.after(0, lambda err_msg=err: self._tg_status.configure(
                            text=f" {err_msg}", text_color=T["danger"]))
            except Exception as e:
                print(f"[TG DEBUG]  Exception: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
                err_msg = f"{type(e).__name__}: {str(e)}"
                self.after(0, lambda msg=err_msg: self._tg_status.configure(
                    text=f" {msg}", text_color=T["danger"]))
        threading.Thread(target=_send, daemon=True).start()

    def _tg_get_chat_id(self):
        """Попытаться получить Chat ID из последнего сообщения боту"""
        token = self._tg_token.get().strip()
        if not token:
            self._tg_status.configure(text=tr("tg_enter_token_first"), text_color=T["warn"])
            return
        self._tg_status.configure(text=tr("tg_getting_chat_id"), text_color=T["text_dim"])
        def _get():
            try:
                import requests
                import json
                url = f"https://api.telegram.org/bot{token}/getUpdates"
                print(f"[TG DEBUG] Получаю обновления: {url}")
                r = requests.get(url, timeout=8)
                print(f"[TG DEBUG] Статус: {r.status_code}")
                print(f"[TG DEBUG] Ответ: {r.text[:500]}")

                if r.status_code == 200:
                    data = r.json()
                    if data.get("ok") and data.get("result"):

                        last_msg = data["result"][-1]
                        msg_obj = last_msg.get("message") or last_msg.get("callback_query", {}).get("message", {})
                        chat_id = msg_obj.get("chat", {}).get("id")
                        if chat_id:
                            print(f"[TG DEBUG] Найден Chat ID: {chat_id}")
                            self.after(0, lambda cid=str(chat_id): self._tg_chat.delete(0, "end") or self._tg_chat.insert(0, str(cid)))
                        self.after(0, lambda: self._tg_status.configure(
                            text=f" Chat ID установлен: {chat_id}", text_color=T["safe"]))
                    else:
                        self.after(0, lambda: self._tg_status.configure(
                            text=tr("tg_history_empty"), text_color=T["warn"]))
                else:
                    self.after(0, lambda: self._tg_status.configure(
                        text=f" Ошибка {r.status_code}", text_color=T["danger"]))
            except Exception as e:
                print(f"[TG DEBUG] Exception: {e}")
                self.after(0, lambda msg=str(e): self._tg_status.configure(
                    text=f" {msg}", text_color=T["danger"]))
        threading.Thread(target=_get, daemon=True).start()

    def _apply_theme(self):
        CFG["theme"] = self._theme_var.get(); CFG["accent"] = self._accent_var.get()
        # Do not persist to disk here; Save All will persist user changes
        try:
            self.app_ref.apply_appearance()
        except Exception:
            pass
        messagebox.showinfo(tr("appearance"), "Appearance applied.")

    def _save_all(self):
        CFG["theme"] = self._theme_var.get()
        CFG["accent"] = self._accent_var.get()
        CFG["auto_block"]       = self._auto_block.get()
        CFG["log_to_file"]      = self._log_file.get()
        CFG["demo_mode"]        = self._demo_var.get()
        CFG["ai_auto_fallback"] = self._ai_fallback.get()
        CFG["ai_log_dialogs"]   = self._ai_log.get()
        try: CFG["max_table_rows"] = int(self._max_rows.get())
        except ValueError: pass
        CFG["language"] = self._lang_var.get()
        CFG["tg_token"]   = self._tg_token.get().strip()
        CFG["tg_chat_id"] = self._tg_chat.get().strip()
        
        # Save selected adapter if user changed it in settings
        if hasattr(self, '_adapter_var'):
            new_adapter = self._adapter_var.get().strip()
            if new_adapter:
                if self.app_ref._adapter_exists(new_adapter):
                    CFG["adapter"] = new_adapter
                    try:
                        self.app_ref.restart_capture(new_adapter)
                    except Exception:
                        pass
                else:
                    messagebox.showwarning("Adapter not found", f"Adapter '{new_adapter}' is not available on this system.")

        # Save new notification settings
        CFG["email_server"] = getattr(self, '_notif_email_server', ctk.CTkEntry).get().strip() if hasattr(self, '_notif_email_server') else ""
        CFG["email_port"] = getattr(self, '_notif_email_port', ctk.CTkEntry).get().strip() if hasattr(self, '_notif_email_port') else ""
        CFG["email_user"] = getattr(self, '_notif_email_user', ctk.CTkEntry).get().strip() if hasattr(self, '_notif_email_user') else ""
        CFG["email_password"] = getattr(self, '_notif_email_password', ctk.CTkEntry).get().strip() if hasattr(self, '_notif_email_password') else ""
        CFG["email_recipient"] = getattr(self, '_notif_email_recipient', ctk.CTkEntry).get().strip() if hasattr(self, '_notif_email_recipient') else ""
        CFG["discord_webhook"] = self._notif_discord_webhook.get().strip() if hasattr(self, '_notif_discord_webhook') else ""
        CFG["slack_webhook"] = self._notif_slack_webhook.get().strip() if hasattr(self, '_notif_slack_webhook') else ""
        CFG["system_toasts"] = self._notif_system_toasts.get() if hasattr(self, '_notif_system_toasts') else False
        
        # Save integration settings
        CFG["virustotal_api"] = self._int_virustotal_api.get().strip() if hasattr(self, '_int_virustotal_api') else ""
        CFG["abuseipdb_api"] = self._int_abuseipdb_api.get().strip() if hasattr(self, '_int_abuseipdb_api') else ""
        
        # Save config/backup settings
        CFG["auto_backup"] = self._auto_backup.get() if hasattr(self, '_auto_backup') else False
        CFG["backup_interval"] = self._backup_interval.get().strip() if hasattr(self, '_backup_interval') else "24"
        
        # Persisting to disk moved to Save All; keep in-memory state only here
        try:
            self.app_ref.apply_appearance()
        except Exception:
            pass
        try:
            self.app_ref.apply_language(CFG.get("language", "en"))
        except Exception:
            pass
        try:
            self.app_ref.apply_mode(CFG.get("demo_mode", True))
        except Exception:
            pass
        try:
            save_config(CFG)
        except Exception:
            logging.exception("Failed to persist settings")
        # Persist AI API keys as part of Save All (use StringVar values)
        try:
            if hasattr(self, '_ai_gemini_var'):
                CFG['gemini_api_key'] = (self._ai_gemini_var.get() or '').strip()
            if hasattr(self, '_ai_openai_var'):
                CFG['openai_api_key'] = (self._ai_openai_var.get() or '').strip()
            if hasattr(self, '_ai_claude_var'):
                CFG['ai_api_key'] = (self._ai_claude_var.get() or '').strip()
            save_config(CFG)
        except Exception:
            logging.exception('Failed to persist API keys')
        try:
            self.engine.reload_telegram()
        except Exception:
            pass
        self.engine.reload_sigs()
        try:
            self._status.configure(text="  Settings applied.")
        except Exception:
            pass

    def _export_cfg(self):
        try:
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("All", "*.*")],
            )
            if not path: return
            import shutil
            shutil.copyfile(CONFIG_FILE, path)
            messagebox.showinfo(tr("export"), f"Config saved to {path}")
        except Exception as e:
            logging.exception("Failed to export config")

    def _import_cfg(self):
        try:
            path = filedialog.askopenfilename(
                filetypes=[("JSON", "*.json"), ("All", "*.*")],
            )
            if not path: return
            import shutil
            shutil.copyfile(path, CONFIG_FILE)
            global CFG
            CFG = load_config()
            messagebox.showinfo(tr("save"), "Config imported successfully. Please restart the app.")
        except Exception as e:
            logging.exception("Failed to import config")

    def _add_simulate_button(self, parent):
        try:
            btn = ctk.CTkButton(parent, text=tr("simulate_attack"), width=220,
                                fg_color=T["danger"], text_color=T["bg_deep"],
                                font=FONT_HEADER, command=lambda: self.app_ref.simulate_attack())
            btn.pack(anchor="w", padx=24, pady=(8,10))
        except Exception: pass

    def _apply_language(self):
        new = getattr(self, '_lang_var', None)
        if new:
            lang = new.get()
            try:
                self.app_ref.apply_language(lang)
                self._status.configure(text=f"  {tr('language')}: {lang}")
            except Exception:
                logging.exception("Failed to apply language")

class SOCSentinel(ctk.CTk):
    def __init__(self):
        logging.info("[SOCSentinel] __init__ started")
        ctk.set_appearance_mode("Dark" if CFG["theme"]=="dark" else "Light")
        logging.info("[SOCSentinel] CTk appearance mode set")
        super().__init__()
        logging.info("[SOCSentinel] CTk.__init__() completed")
        try:
            logging.info("[SOCSentinel] Setting i18n root")
            i18n.set_root(self)
            logging.info("[SOCSentinel] i18n root set, changing language")
            try: i18n.change_language(CFG.get("language", "en"))
            except Exception: logging.exception("[SOCSentinel] i18n.change_language failed")
        except Exception: logging.exception("[SOCSentinel] i18n setup failed")
        logging.info("[SOCSentinel] Setting window title and geometry")
        self.title("SOC SENTINEL v2  AI Cybersecurity Dashboard")
        self.geometry("1860x1020"); self.minsize(1280,780)
        self.configure(fg_color=T["bg_deep"]); self.withdraw()
        logging.info("[SOCSentinel] Window configured, creating ThreatEngine")
        self.bot              = None
        self.engine           = ThreatEngine(self.bot)
        logging.info("[SOCSentinel] ThreatEngine created")
        self.adapter          = CFG.get("adapter","")
        self._running         = False
        self._sniff_thread    = None
        self._pkt_queue       = queue.Queue(maxsize=2000)
        self.sidebar_visible  = True
        self.ai_panel_visible = False
        self._current_user    = ("guest","user")

        self._flask_thread: threading.Thread | None = None
        self._flask_running: bool = False
        self._flask_start_time: datetime | None = None
        self._flask_request_count: int = 0

        self._mgmt_buckets: dict            = {}
        self._mgmt_pkt_counter: int         = 0
        self._MGMT_RATE_LIMIT: int          = 4
        self._MGMT_RATE_WINDOW: float       = 1.0
        self._MGMT_LIMITED_TYPES: frozenset = frozenset({"Dot11Deauth", "Dot11Disas"})

        if self.adapter and not self._adapter_exists(self.adapter):
            self.adapter = ""
        # Do not auto-select a default network adapter.
        # The adapter should only be set when the user explicitly chooses one.

        self._agg_lock           = threading.Lock()
        self._agg_pkt_total: int = 0
        self._agg_deauth_counts: dict = {}
        self._DEAUTH_FLOOD_THRESH: int = 10

        self._pull_tick: int = 0
        self._CHART_EVERY: int = 5

        logging.info("[SOCSentinel] __init__ completed, scheduling auth")
        self.after(100, self._do_auth)

    def _do_auth(self):
        logging.info("[SOCSentinel] _do_auth called, showing AuthWindow")
        auth = AuthWindow(self)
        logging.info("[SOCSentinel] AuthWindow created, waiting for window")
        self.wait_window(auth)
        logging.info("[SOCSentinel] AuthWindow closed")
        if auth.result is None: self.destroy(); return
        self._current_user = auth.result
        username, role = auth.result
        self.title(f"SOC SENTINEL v2    {username.upper()}  [{tr(role).upper()}]")
        ttk_style(); self._build(); self.deiconify()
        self.apply_mode(CFG.get("demo_mode",True))
        self._drain_queue()
        self._pull_deauth_stats()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._schedule_global_gc()
        if CFG.get("web_autostart", False):
            self._start_flask_api()

    def apply_mode(self, demo: bool):
        self._running = False
        try:
            self.engine.set_demo_mode(False)
        except Exception:
            dg = getattr(self.engine, '_demo_gen', None)
            if dg:
                try: dg.stop()
                except Exception: pass
        self.engine.reset_stats()
        if demo:
            CFG["demo_mode"] = True; self.engine.set_demo_mode(True)
            if hasattr(self,'pages'):
                self.pages["logs"].append("SIMULATION mode active.","INFO")
                self.status_lbl.configure(text=f"  {tr('simulation_mode')}", text_color=T["warn"])
        else:
            CFG["demo_mode"] = False
            if not SCAPY_AVAILABLE:
                messagebox.showwarning("Scapy Missing",
                    "Install: pip install scapy\nWindows: also install Npcap.\n\nFalling back to simulation.")
                CFG["demo_mode"] = True; self.engine.set_demo_mode(True); return
            if not self.adapter:
                messagebox.showwarning("No Adapter",
                    "Select a network adapter in Settings  Network Interface first.")
                CFG["demo_mode"] = True; self.engine.set_demo_mode(True); return
            self._start_capture(self.adapter)
            if hasattr(self,'pages'):
                self.pages["logs"].append(f"LIVE mode on {self.adapter}.","INFO")
                self.status_lbl.configure(text=f"  {tr('monitoring')}", text_color=T["safe"])
        # Persisting config is handled by Save All; do not write to disk here

    def simulate_attack(self):
        fake_ip = "192.168.1.250"
        # Fixed severity to uppercase CRITICAL (matches rest of the system!)
        self.engine._raise_alert("SYN_FLOOD", fake_ip, "CRITICAL", 1500)
        # Also increment threat_count to fix dashboard KPI showing 0!
        with self.engine.lock:
            self.engine.threat_count += 1
        _toast_async("SOC Sentinel - Alert", f"Simulated attack from {fake_ip} - CRITICAL")

    def _drain_queue(self):
        import logging
        q = self.engine.result_q
        qsize = q.qsize()
        logging.debug(f"[DBG-03] _drain_queue(): qsize={qsize}")

        if qsize > 500:
            drop = qsize - 100
            for _ in range(drop):
                try: q.get_nowait()
                except queue.Empty: break
            BATCH = 5
            next_ms = 200
        elif qsize > 100:
            BATCH = 10
            next_ms = 100
        else:
            BATCH = 20
            next_ms = 50

        processed = 0
        while processed < BATCH:
            try: r = q.get_nowait()
            except queue.Empty: break
            except Exception: break

            try:
                src     = r.get("src", "?")
                dst     = r.get("dst", "?")
                app     = r.get("app", "?")
                size    = r.get("size", 0)
                status  = r.get("status", "?")
                threats = r.get("threats", [])
                is_wifi = r.get("wifi_threat", False)

                try:
                    if is_wifi or processed % 3 == 0:
                        self.pages["dash"].add_live_row(src, dst, app, size, status)
                except Exception: pass

                try:
                    if not r.get("_display_only"):
                        self.pages["analyzer"].add_packet(r)
                except Exception: pass

                try:
                    topo = self.pages.get("topology")
                    if topo and hasattr(topo, "record_host_activity") and src and app:
                        topo.record_host_activity(src, app)
                except Exception: pass

                try:
                    if not r.get("_display_only"):
                        db = get_db()
                        if db:
                            rec = {
                                "time": r.get("time"), "src": src, "dst": dst,
                                "proto": r.get("proto"), "app": app, "size": size,
                                "status": status, "threats": threats,
                                "vendor": r.get("vendor"),
                            }
                            db.insert_packet(rec)
                except Exception: pass

                if threats:
                    for t in threats:
                        try:
                            if isinstance(t, (list, tuple)) and len(t) >= 3:
                                ttype, actor, sev = t[0], t[1], t[2]
                            elif isinstance(t, str):
                                ttype = t; actor = src; sev = r.get("wifi_sev", "HIGH")
                            else: continue
                            msg = f"{ttype}  |  {actor}  |  {sev}"
                            lvl = "CRITICAL" if sev == "CRITICAL" else "WARN"
                            try: self.pages["logs"].append(msg, lvl)
                            except Exception: pass
                        except Exception: pass

                processed += 1
            except Exception:
                logging.exception("Error while draining queue")

        self.after(next_ms, self._drain_queue)

    def _build(self):
        self.grid_columnconfigure(0, minsize=228)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, minsize=0)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=228, fg_color=T["bg_panel"],
                                     corner_radius=0, border_width=1,
                                     border_color=T["border"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        lg = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        lg.pack(fill="x", padx=16, pady=(28,16))
        ctk.CTkLabel(lg, text="SOC SENTINEL", font=(FONT_FAMILY_MONO,16,"bold"),
                     text_color=T["accent"]).pack()
        u, role = self._current_user
        badge = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        badge.pack(fill="x", padx=16, pady=(16,4))
        ctk.CTkLabel(badge, text=u,
                     font=FONT_SMALL, text_color=T["accent"]).pack(side="left",padx=10,pady=6)
        ctk.CTkLabel(badge, text=tr(role).upper(), font=FONT_TINY,
                     text_color=T["text_muted"]).pack(side="right",padx=8)
        ctk.CTkFrame(self.sidebar, fg_color=T["border"], height=1
                     ).pack(fill="x",padx=16,pady=(0,16))
        self._nav_btns = {}
        for pid, icon, label_key in [
            ("dash",     "","dash"),
            ("analyzer", "","analyzer"),
            ("threats",  "","threats"),
            ("active_blocks", "","active_blocks"),
            ("web",      "","web"),
            ("topology", "","topology"),
            ("logs",     "","logs"),
            ("settings", "", "settings"),
        ]: self._make_nav(pid, icon, label_key)
        ctk.CTkFrame(self.sidebar, fg_color=T["border"], height=1
                     ).pack(fill="x",padx=16,pady=8,side="bottom")
        bot = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bot.pack(side="bottom", fill="x", padx=16, pady=(0,16))
        self.status_lbl  = ctk.CTkLabel(bot, text=f"  {tr('idle')}", font=FONT_SMALL,
                                         text_color=T["warn"])
        self.status_lbl.pack()
        self.adapter_lbl = ctk.CTkLabel(bot, text=self.adapter[:24] or "",
                                         font=FONT_TINY, text_color=T["text_dim"])
        self.adapter_lbl.pack()
        self._web_url_lbl = ctk.CTkLabel(bot, text=tr("web_label"), font=FONT_TINY,
                                          text_color=T["safe"], cursor="hand2")
        self._web_url_lbl.pack(pady=(4, 0))
        self._web_url_lbl.bind("<Button-1>", lambda e: self.show_page("web"))

        self.content = ctk.CTkFrame(self, fg_color=T["bg_deep"], corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.ai_panel = AIAssistantPanel(self.content, self.engine, width=380)

        topbar = ctk.CTkFrame(self.content, fg_color=T["bg_card"], corner_radius=12,
                              border_width=1, border_color=_adjust_color(T["border"],0.9),
                              height=64)
        topbar.place(relx=0, y=12, relwidth=1.0, anchor='nw')

        left = ctk.CTkFrame(topbar, fg_color="transparent")
        left.pack(side="left", padx=16, pady=8)
        ctk.CTkLabel(left, text="", font=(FONT_FAMILY_MONO,22), text_color=T["accent"]).pack(side="left")
        ctk.CTkLabel(left, text="SOC SENTINEL v2", font=(FONT_FAMILY_SANS_BOLD,12), text_color=T["text_primary"]).pack(side="left", padx=(8,0))

        right = ctk.CTkFrame(topbar, fg_color="transparent")
        right.pack(side="right", padx=16, pady=8)

        self._sidebar_btn = ctk.CTkButton(
            right, text=f"  {tr('menu')}", width=120, height=44,
            fg_color=T["bg_card"], text_color=T["text_dim"],
            hover_color=_adjust_color(T["bg_hover"],1.05),
            font=(FONT_FAMILY_SANS_BOLD,12), corner_radius=12,
            border_width=1, border_color=T["border"], command=self._toggle_sidebar)
        self._sidebar_btn.pack(side="left", padx=(0,8))

        self._ai_btn = ctk.CTkButton(
            right, text=f"  {tr('assistant')}", width=140, height=44,
            fg_color=_adjust_color(T["accent"],0.9), text_color=T["bg_deep"],
            hover_color=_adjust_color(T["accent"],1.15),
            font=(FONT_FAMILY_SANS_BOLD,12), corner_radius=12, border_width=0,
            command=self._toggle_ai)
        self._ai_btn.pack(side="left")

        self.pages = {
            "dash":         DashboardPage(self.content, self.engine),
            "analyzer":     AnalyzerPage(self.content, self.engine),
            "threats":      ThreatPage(self.content, self.engine),
            "active_blocks": ActiveBlocksPage(self.content, self.engine),
            "web":          WebAccessPage(self.content, self.engine, self),
            "topology":     TopologyPage(self.content, self.engine),
            "logs":         LogsPage(self.content, self.engine),
            "settings":     SettingsPage(self.content, self.engine, self, self._current_user),
        }
        for p in self.pages.values():
            p.grid(row=0, column=0, sticky="nsew")
        self.show_page("dash")

        try:
            self.pages["settings"]._add_simulate_button(self.pages["settings"])
        except Exception: pass

        try:
            CFG["demo_mode"] = False
        except Exception: pass

        self.after(200, lambda: [self._sidebar_btn.lift(), self._ai_btn.lift()])
        def _safe_lift(e=None):
            try:
                if self._sidebar_btn.winfo_exists(): self._sidebar_btn.lift()
                if self._ai_btn.winfo_exists():      self._ai_btn.lift()
            except Exception: pass
        self.bind("<Configure>", _safe_lift)

        def _hotkey_ctrl(e):
            ks = (getattr(e, 'keysym', '') or '').lower()
            ch = (getattr(e, 'char', '') or '').lower()
            if ks in ("m", "ь") or ch in ("m", "ь"):
                self._toggle_sidebar()
        self.bind_all('<Control-KeyPress>', _hotkey_ctrl)
        self.bind_all('<Control-m>', _hotkey_ctrl)
        self.bind_all('<Control-M>', _hotkey_ctrl)

        def _hotkey_alt(e):
            ks = (getattr(e, 'keysym', '') or '').lower()
            ch = (getattr(e, 'char', '') or '').lower()
            if ks in ("a", "ф") or ch in ("a", "ф"):
                self._toggle_ai()
        self.bind_all('<Alt-KeyPress>', _hotkey_alt)
        self.bind_all('<Alt-a>', _hotkey_alt)
        self.bind_all('<Alt-A>', _hotkey_alt)

        try:
            self._ai_fab = ctk.CTkButton(self.content, text=tr('assistant')[0], width=44, height=44,
                                         fg_color=_adjust_color(T["accent"],0.92),
                                         hover_color=_adjust_color(T["accent"],1.08),
                                         text_color=T["bg_deep"], corner_radius=12,
                                         command=self._toggle_ai)
            self._ai_fab.place(relx=1.0, rely=1.0, x=-24, y=-24, anchor='se')
            self._ai_fab.lift()
        except Exception:
            logging.exception("Failed to create AI floating button")

    def _start_flask_api(self):
        if not FLASK_AVAILABLE:
            logging.warning("[Web] pip install flask flask-cors")
            return
        if not CFG.get("web_enabled", True):
            return
        if self._flask_running:
            return
        import weakref
        from utils.network import get_connection_urls, open_firewall_port, get_primary_lan_ip
        engine_ref = weakref.ref(self.engine)
        flask_app  = _build_flask_app(engine_ref, app_ref=weakref.ref(self))
        port = int(CFG.get("web_port", 5000))
        if CFG.get("web_firewall", True):
            try:
                open_firewall_port(port)
            except Exception:
                pass
        primary = get_primary_lan_ip()
        if primary:
            logging.info("[Web] Дашборд: http://%s:%s (та же Wi-Fi сеть)", primary, port)
            try:
                self._web_url_lbl.configure(text=f" http://{primary}:{port}")
            except Exception:
                pass

        def _run_flask():
            import logging as _lg
            _lg.getLogger("werkzeug").setLevel(_lg.ERROR)
            self._flask_running = True
            self._flask_start_time = datetime.now()
            self._flask_request_count = 0
            try:
                flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False, threaded=True)
            finally:
                self._flask_running = False
        self._flask_thread = threading.Thread(target=_run_flask, daemon=True, name="FlaskWebThread")
        self._flask_thread.start()

    def _stop_flask_api(self):
        if not self._flask_running:
            return
        try:
            import requests
            port = int(CFG.get("web_port", 5000))
            # Try to send a request to stop, but since Flask doesn't have a built-in stop, we'll just note it's stopped
            # In reality, we need a more robust way, but for this app, we'll toggle the flag
            self._flask_running = False
            self._flask_start_time = None
            logging.info("[Web] Web server stopped")
        except Exception as e:
            logging.exception("[Web] Error stopping server")

    def _restart_flask_api(self):
        self._stop_flask_api()
        self.after(500, self._start_flask_api)
    def _make_nav(self, pid, icon, label):
        label_text = tr(label)
        btn = ctk.CTkButton(
            self.sidebar, text=f"  {icon}   {label_text}", anchor="w", height=48,
            fg_color="transparent", hover_color=_adjust_color(T["bg_hover"],1.03),
            text_color=T["text_dim"], font=(FONT_FAMILY_SANS_BOLD,11),
            corner_radius=DEFAULT_CORNER, command=lambda p=pid: self.show_page(p))
        btn.pack(fill="x", padx=10, pady=2); self._nav_btns[pid] = btn

    def show_page(self, name):
        for pid,btn in self._nav_btns.items():
            btn.configure(fg_color=T["bg_hover"] if pid==name else "transparent",
                          text_color=T["accent"]  if pid==name else T["text_dim"])
        for p in self.pages.values(): p.grid_remove()
        self.pages[name].grid(row=0, column=0, sticky="nsew")
        try: self._current_page = name
        except Exception: pass
        try: self._sidebar_btn.lift(); self._ai_btn.lift()
        except Exception: pass

    def apply_language(self, lang: str):
        try:
            try: i18n.change_language(lang)
            except Exception: pass
            CFG["language"] = lang
        except Exception:
            logging.exception("Failed to save language to config")
        try:
            self._rebuild_ui_preserve_state()
        except Exception:
            logging.exception("Failed to rebuild UI after language change")

    def _rebuild_ui_preserve_state(self):
        cur_page = getattr(self, '_current_page', 'dash')
        for name in ("sidebar","content","ai_panel","_ai_fab","_sidebar_btn","_ai_btn",):
            w = getattr(self, name, None)
            try:
                if w is not None and hasattr(w, 'destroy'):
                    w.destroy()
            except Exception: pass
        try:
            if hasattr(self, 'pages'):
                for p in list(self.pages.values()):
                    try: p.destroy()
                    except Exception: pass
        except Exception: pass
        try:
            self._build()
            try: self.show_page(cur_page)
            except Exception: self.show_page('dash')
        except Exception:
            logging.exception("Error rebuilding UI")

    def apply_appearance(self):
        try:
            CFG["theme"] = CFG.get("theme", "dark")
            CFG["accent"] = CFG.get("accent", "cyan")
            ctk.set_appearance_mode("Dark" if CFG["theme"] == "dark" else "Light")
            global T
            T = build_theme(CFG["theme"], CFG["accent"])
            self._rebuild_ui_preserve_state()
        except Exception:
            logging.exception("Failed to apply appearance dynamically")

    def _toggle_sidebar(self):
        if self.sidebar_visible:
            self.sidebar.grid_remove(); self.grid_columnconfigure(0,minsize=0)
            self.sidebar_visible = False; self._sidebar_btn.configure(text=tr("menu"))
        else:
            self.sidebar.grid(row=0,column=0,sticky="nsew")
            self.grid_columnconfigure(0,minsize=228)
            self.sidebar_visible = True; self._sidebar_btn.configure(text=tr("close"))
        try: self._sidebar_btn.lift(); self._ai_btn.lift()
        except Exception: pass

    def _toggle_ai(self):
        if self.ai_panel_visible:
            try: self.ai_panel.place_forget()
            except Exception: pass
            self.ai_panel_visible = False
            self._ai_btn.configure(fg_color=T["accent"], text=tr("assistant"))
        else:
            try:
                self.ai_panel.place(relx=1.0, x=-20, y=84, anchor='ne', relheight=0.88)
                self.ai_panel.lift()
            except Exception: pass
            self.ai_panel_visible = True
            self._ai_btn.configure(fg_color=T["danger"], text="X")
        try:
            self._sidebar_btn.lift(); self._ai_btn.lift()
        except Exception: pass

    def _select_default_adapter(self) -> str:
        try:
            adapters = psutil.net_if_addrs()
            if not adapters:
                return ""
            candidates = []
            for name, addrs in adapters.items():
                lname = name.lower()
                if lname.startswith(("loopback", "lo")):
                    continue
                ips = [a.address for a in addrs if a.family == socket.AF_INET and a.address not in ("127.0.0.1", "0.0.0.0")]
                if not ips:
                    continue
                if name.strip() == "":
                    continue
                kind = "other"
                if any(k in lname for k in ("wi-fi", "wifi", "wlan", "wireless")): kind = "wifi"
                elif any(k in lname for k in ("eth", "ethernet", "lan")): kind = "ethernet"
                candidates.append((kind, name))
            if not candidates:
                return ""
            priority = {"wifi": 0, "ethernet": 1, "other": 2}
            candidates.sort(key=lambda item: (priority.get(item[0], 2), item[1]))
            return candidates[0][1]
        except Exception:
            return ""

    def _adapter_exists(self, adapter_name: str) -> bool:
        try:
            if not adapter_name:
                return False
            return adapter_name in psutil.net_if_addrs()
        except Exception:
            return False

    def _start_capture(self, adapter):
        if not SCAPY_AVAILABLE: return
        self._running = False
        if self._sniff_thread and self._sniff_thread.is_alive(): time.sleep(0.4)
        # Apply adapter in-memory only; do not persist to disk here
        self.adapter = adapter; CFG["adapter"] = adapter
        self.adapter_lbl.configure(text=adapter[:24])
        self._running = True
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True,
                                               name="ScapySnifferThread")
        self._sniff_thread.start()

    def restart_capture(self, adapter):
        self._running = False; time.sleep(0.5); self._start_capture(adapter)

    def _sniff_loop(self):
        iface = self.adapter
        bpf_filter = "" if CFG.get("deep_http_capture", False) else "not (tcp port 443 or tcp port 80)"

        def _log(msg: str, lvl: str = "INFO"):
            try: self.after(0, lambda m=msg, l=lvl: self.pages["logs"].append(m, l))
            except Exception: pass

        _log(f"Sniffer started: iface={iface!r}  BPF={bpf_filter!r}")

        kwargs = dict(iface=iface, prn=self._handle_pkt, store=0, filter=bpf_filter)
        while self._running:
            try:
                scapy.sniff(timeout=2, **kwargs)
            except OSError as e:
                _log(f"Sniffer OSError: {e}", "CRITICAL"); time.sleep(3)
            except Exception as e:
                _log(f"Sniffer error: {e}", "CRITICAL"); time.sleep(3)

        _log("Sniffer stopped.")

    def _handle_pkt(self, pkt) -> None:
        if not self._running:
            return

        try:
            with self._agg_lock:
                self._agg_pkt_total += 1

            if pkt.haslayer("EAPOL"):
                if self.engine.result_q.qsize() < 100:
                    self.engine.submit(pkt)
                return

            pkt_type: str = type(pkt.payload).__name__
            if pkt_type in self._MGMT_LIMITED_TYPES:
                src_mac: str = pkt.addr2 or "ff:ff:ff:ff:ff:ff"
                with self._agg_lock:
                    self._agg_deauth_counts[src_mac] = (
                        self._agg_deauth_counts.get(src_mac, 0) + 1
                    )
                return

            if self.engine.result_q.qsize() >= 50:
                return
            self.engine.submit(pkt)

        except Exception:
            pass

    def _pull_deauth_stats(self) -> None:
        self._pull_tick += 1

        if not self._running:
            self.after(300, self._pull_deauth_stats)
            return

        with self._agg_lock:
            pkt_total           = self._agg_pkt_total
            deauth_snapshot     = self._agg_deauth_counts
            self._agg_pkt_total     = 0
            self._agg_deauth_counts = {}

        try:
            now_str = datetime.now().strftime("%H:%M:%S")
            flood_macs = {
                mac: cnt for mac, cnt in deauth_snapshot.items()
                if cnt >= self._DEAUTH_FLOOD_THRESH
            }

            if flood_macs:
                top_mac      = max(flood_macs, key=flood_macs.__getitem__)
                top_count    = flood_macs[top_mac]
                total_deauth = sum(deauth_snapshot.values())

                alert = {
                    "time":     now_str,
                    "type":     "DEAUTH_FLOOD",
                    "actor":    top_mac,
                    "severity": "CRITICAL",
                    "size":     total_deauth,
                    "detail": (
                        f"{len(flood_macs)} source(s), "
                        f"{total_deauth} frames/300ms  "
                        f"top offender: {top_mac} ({top_count} pkts)"
                    ),
                }

                if self.engine.lock.acquire(timeout=0.05):
                    try:
                        self.engine.alerts.append(alert)
                    finally:
                        self.engine.lock.release()

                def _fire_callbacks(a=alert):
                    for cb in getattr(self.engine, "alert_callbacks", []):
                        try:
                            cb(a)
                        except Exception:
                            pass

                threading.Thread(
                    target=_fire_callbacks,
                    daemon=True,
                    name="AlertCbThread",
                ).start()

                try:
                    self.pages["logs"].append(
                        f"DEAUTH_FLOOD | {top_mac} | {top_count} pkt/300ms | CRITICAL",
                        "CRITICAL",
                    )
                except Exception:
                    pass

        except Exception:
            pass

        try:
            if pkt_total >= 0:
                pps_estimate = int(pkt_total * (1000 / 300))
                dash = self.pages.get("dash")
                if dash:
                    for card in getattr(dash, "_kpi_cards", {}).values():
                        if "pps" in getattr(card, "_title_raw", "").lower():
                            card.set(f"{pps_estimate:,}")
                            break
        except Exception:
            pass

        active_flood = any(c >= self._DEAUTH_FLOOD_THRESH
                           for c in deauth_snapshot.values())
        do_chart = (
            (self._pull_tick % 7 == 0)
            and (self.engine.result_q.qsize() < 20)
            and (not active_flood)
        )
        if do_chart:
            try:
                dash = self.pages.get("dash")
                if dash and hasattr(dash, "_refresh_charts"):
                    dash._refresh_charts()
            except Exception:
                pass

        self.after(300, self._pull_deauth_stats)

    def _schedule_global_gc(self, interval_ms: int = 60_000):
        def _gc_tick():
            try: gc.collect()
            except Exception: pass
            try: self.after(interval_ms, _gc_tick)
            except Exception: pass
        self.after(interval_ms, _gc_tick)

    def _on_close(self):
        self._running = False

        try:
            if hasattr(self, 'pages') and "logs" in self.pages:
                self.pages["logs"]._file_q.put_nowait(None)
        except Exception:
            pass
        self.engine.shutdown()
        self.destroy()

if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                messagebox.showwarning(tr("admin_required_title"), tr("admin_required_msg"))
        except Exception: pass
    else:
        try:
            import os
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                print("[WARNING] SOC Sentinel should run as root on Linux for packet capture.")
                print("Run: sudo python WifiSecuritySystem.py")
        except Exception:
            pass
    if not SCAPY_AVAILABLE:
        print("="*60)
        print("WARNING: scapy not installed  running in simulation mode.")
        print("pip install scapy")
        print("="*60)
    set_dpi_awareness()
    app = SOCSentinel()
    app.mainloop()
