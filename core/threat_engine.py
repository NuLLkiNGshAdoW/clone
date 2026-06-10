import threading
import queue
import collections
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import deque, defaultdict

from utils.config import load_config
from .detector import ThreatDetector
from core.database import get_db
from core.active_response import ActiveResponse
from core.device_fingerprint import DeviceFingerprinter
from core.plugin_loader import load_all_plugins
from pathlib import Path
import re
from core.whitelist import is_whitelisted

# Simple OUI vendor map loader (small footprint) — supports partial matches for common vendors
_OUI_CACHE = {}

def load_oui(path=None):
    """Load a minimal OUI lookup table from a file or embedded list.
    Expected format: hex OUI (e.g. 001A2B) , Vendor Name
    """
    global _OUI_CACHE
    if _OUI_CACHE: return _OUI_CACHE
    # try builtin small map first
    _OUI_CACHE = {
        "A4:5E:60": "Apple",
        "44:38:39": "Samsung",
        "3C:5A:B4": "Xiaomi",
        "00:1A:2B": "Cisco",
        "F0:D1:A9": "Intel",
    }
    # attempt to load custom OUI file near project root
    try:
        p = Path(path) if path else Path("oui.txt")
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                for ln in f:
                    parts = re.split(r"\s+", ln.strip(), maxsplit=1)
                    if not parts:
                        continue
                    oui_raw = parts[0].upper()
                    # normalize OUI to XX:YY:ZZ
                    oui = oui_raw.replace('-', '').replace('.', '')
                    if len(oui) >= 6:
                        norm = ":".join([oui[i:i+2] for i in range(0,6,2)])
                        _OUI_CACHE[norm] = parts[1].strip() if len(parts) > 1 else parts[0]
    except Exception:
        pass
    return _OUI_CACHE

def lookup_vendor(mac: str) -> str:
    if not mac: return "Unknown"
    m = mac.upper().replace('-',':')
    parts = m.split(':')
    if len(parts) < 3: return "Unknown"
    key = ":".join(parts[:3])
    # try direct
    v = _OUI_CACHE.get(key)
    if v: return v
    # try short-match
    for k, name in _OUI_CACHE.items():
        if key.startswith(k): return name
    return "Unknown"

# Demo data generator moved into core so engine owns demo lifecycle
class DemoDataGenerator:
    APPS = ["HTTPS","YouTube/Google","DNS","AWS","Google","Microsoft 365",
            "Telegram","Cloudflare","LAN","General","Netflix","Zoom","GitHub"]
    STATUSES = [" SAFE"]*8 + ["⚠ PORT_SCAN","⚠ SYN_FLOOD","⚠ DNS_TUNNEL","🚫 BLOCKED"]
    SEVERITY = ["CRITICAL","HIGH","MEDIUM","LOW"]

    # colors (avoid GUI dependency)
    _COLOR_SAFE = "#00FF88"
    _COLOR_DANGER = "#FF3B5C"
    _COLOR_INFO = "#00D4FF"

    def __init__(self, engine):
        self.engine = engine
        self._running = False
        self._thread  = None

    def start(self):
        if self._running: return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="demo_gen")
        self._thread.start()

    def stop(self):
        self._running = False

    def _rand_ip(self, private=True):
        if private: return f"192.168.{random.randint(1,5)}.{random.randint(2,250)}"
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _loop(self):
        tick = 0
        while self._running:
            now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            batch   = random.randint(1, 4)
            with self.engine.lock:
                for _ in range(batch):
                    src    = self._rand_ip(True)
                    dst    = self._rand_ip(random.random() < 0.3)
                    app    = random.choice(self.APPS)
                    size   = random.randint(64, 1500)
                    status = random.choice(self.STATUSES)
                    threats = []
                    if "SAFE" not in status and "BLOCKED" not in status:
                        ttype = status.replace("⚠ ", "")
                        sev   = random.choice(self.SEVERITY[:2])
                        threats = [(ttype, src, sev)]
                        self.engine._raise_alert(ttype, src, sev, size)
                        self.engine.threat_count += 1
                    self.engine.packet_count  += 1
                    self.engine.packet_stats["total"] += 1
                    self.engine.packet_stats["bytes"] += size
                    self.engine.app_counts[app]       += 1
                    proto = random.choice(["TCP","TCP","TCP","UDP","ICMP"])
                    self.engine.proto_counts[proto]   += 1
                    if app == "DNS": self.engine.proto_counts["DNS"] += 1
                    # include vendor info derived from ARP table if available
                    vendor = None
                    try:
                        mac = self.engine.arp_table.get(src)
                        if mac:
                            load_oui()
                            vendor = lookup_vendor(mac)
                    except Exception:
                        vendor = None
                    result = {"pkt": None, "status": status,
                              "color": self._COLOR_SAFE if "SAFE" in status else self._COLOR_DANGER,
                              "threats": threats, "app": app, "src": src, "dst": dst,
                              "size": size, "time": now_str, "proto": proto, "vendor": vendor}
                    try: self.engine.result_q.put_nowait(result)
                    except queue.Full:
                        logging.debug("Demo generator: result queue full, dropping demo packet")
                if tick % 20 == 0:
                    ip  = self._rand_ip(True)
                    mac = ":".join(f"{random.randint(0,255):02X}" for _ in range(6))
                    self.engine.arp_table[ip] = mac
            tick += 1
            time.sleep(0.05 + random.uniform(0, 0.03))

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def _get_sigs_from_cfg(cfg):
    return {
        "PORT_SCAN":   {"thresh": cfg.get("scan_thresh", 15), "window": 5,  "sev": "HIGH"},
        "SYN_FLOOD":   {"thresh": cfg.get("syn_thresh", 100),  "window": 2,  "sev": "CRITICAL"},
        "ARP_SPOOF":   {"thresh": 3,                                "window": 3,  "sev": "CRITICAL"},
        "DNS_TUNNEL":  {"thresh": 5,                                "window": 10, "sev": "HIGH"},
        "ICMP_FLOOD":  {"thresh": cfg.get("icmp_thresh", 50),    "window": 2,  "sev": "MEDIUM"},
        "BRUTE_FORCE": {"thresh": 8,                                "window": 30, "sev": "HIGH"},
        "DATA_EXFIL":  {"thresh": cfg.get("data_exfil_kb", 8)*1024, "window": 1,  "sev": "CRITICAL"},
    }


class ThreatEngine:
    def __init__(self, bot=None):
        self.bot = bot
        self.threat_count = 0
        self.packet_count = 0
        self.blocked_ips = set()
        self.alerts = []
        self.packet_stats = collections.defaultdict(int)
        self.proto_counts = collections.defaultdict(int)
        self.app_counts = collections.defaultdict(int)         # накопительный (всё время)
        self.app_counts_recent = collections.defaultdict(int)  # скользящее окно 60 сек
        self._app_recent_ts: deque = deque()  # [(timestamp, app_name), ...]
        self._APP_WINDOW = 60.0  # секунд — окно для "recent" графика
        self.port_scan_track = collections.defaultdict(set)
        self.syn_track = collections.defaultdict(deque)
        self.ip_ts = collections.defaultdict(list)
        self.arp_table = {}
        self.dns_track = collections.defaultdict(list)
        self.icmp_track = collections.defaultdict(list)
        self.ip_rate = collections.defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.Lock()
        self.alert_callbacks = []
        self._packet_callbacks = []
        self._tg_bot = None
        cfg = load_config()
        self.SIGS = _get_sigs_from_cfg(cfg)
        self.proc_map = {}
        self.local_ips = set()

        try:
            import os
            workers = max(4, os.cpu_count() or 4)
        except Exception:
            workers = 4
        self._executor = ThreadPoolExecutor(max_workers=workers)
        self.result_q = queue.Queue(maxsize=20000)

        self._demo = False
        self._demo_gen = None

        self._ips = ActiveResponse(load_config, on_block=self._on_ips_block)
        self._device_fp = DeviceFingerprinter(cfg.get("behavior_score_threshold", 70))
        self._plugins = load_all_plugins(engine=self)

        self._wifi_monitor = None
        if not cfg.get("demo_mode", False):
            try:
                import importlib.util as _ilu
                from pathlib import Path as _Path
                _core_dir    = _Path(__file__).resolve().parent
                _project_dir = _core_dir.parent
                _candidates  = []
                for _d in (_core_dir, _project_dir):
                    for _n in ("Wifi monitor.py", "Wifi_monitor.py", "wifi_monitor.py",
                               "WiFiMonitor.py", "wifi monitor.py"):
                        _candidates.append(_d / _n)
                _WiFiMonitor = None
                for _p in _candidates:
                    if _p.exists():
                        _spec = _ilu.spec_from_file_location(
                            "core.wifi_monitor", _p,
                            submodule_search_locations=[]
                        )
                        _mod = _ilu.module_from_spec(_spec)
                        _mod.__package__ = "core"
                        _mod.__spec__    = _spec
                        import sys as _sys
                        _sys.modules.setdefault("core.wifi_monitor", _mod)
                        _spec.loader.exec_module(_mod)
                        _WiFiMonitor = _mod.WiFiMonitor
                        break
                if _WiFiMonitor is None:
                    raise FileNotFoundError("WiFiMonitor file not found")
                self._wifi_monitor = _WiFiMonitor(engine=self)
                adapter = cfg.get("adapter", "")
                if adapter:
                    self._wifi_monitor.start(adapter)
            except Exception:
                logging.exception("WiFiMonitor init failed")
                self._tg_bot = None
        if self.bot is None:
            self._init_telegram()

        self._proc_running = True
        self._proc_thread = threading.Thread(target=self._proc_loop, daemon=True)
        self._proc_thread.start()

    def set_demo_mode(self, enabled: bool):
        # Create demo generator lazily so core owns demo lifecycle
        self._demo = bool(enabled)
        if enabled:
            if self._demo_gen is None:
                # demo generator implemented inside core
                self._demo_gen = DemoDataGenerator(self)
            try:
                self._demo_gen.start()
            except Exception:
                logging.exception("Failed to start demo generator")
        else:
            if self._demo_gen is not None:
                try:
                    self._demo_gen.stop()
                except Exception:
                    logging.exception("Failed to stop demo generator")

    def reset_stats(self):
        with self.lock:
            self.threat_count = 0; self.packet_count = 0
            self.alerts.clear(); self.packet_stats.clear()
            self.proto_counts.clear(); self.app_counts.clear()
            self.app_counts_recent.clear(); self._app_recent_ts.clear()
            self.port_scan_track.clear(); self.syn_track.clear()
            self.ip_ts.clear(); self.arp_table.clear()
            self.dns_track.clear(); self.icmp_track.clear(); self.ip_rate.clear()
        while not self.result_q.empty():
            try: self.result_q.get_nowait()
            except queue.Empty: break
            except Exception:
                logging.exception("Error clearing result queue")
                break

    def submit(self, pkt):
        try:
            self._executor.submit(self._analyze_and_queue, pkt)
        except RuntimeError:
            logging.exception("Executor not accepting new tasks")

    def _analyze_and_queue(self, pkt):
        try:
            status, color, threats = ("N/A", "#777", [])
            if SCAPY_AVAILABLE:
                status, color, threats = self.analyze(pkt)
            app = self._identify_app(pkt) if SCAPY_AVAILABLE else "Unknown"
            src = pkt[scapy.IP].src if SCAPY_AVAILABLE and pkt.haslayer(scapy.IP) else "?"
            dst = pkt[scapy.IP].dst if SCAPY_AVAILABLE and pkt.haslayer(scapy.IP) else "?"
            size = len(pkt) if hasattr(pkt, '__len__') else 0
            result = {"pkt": pkt, "status": status, "color": color,
                      "threats": threats, "app": app, "src": src, "dst": dst,
                      "size": size, "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                      "proto": ("TCP" if pkt.haslayer(scapy.TCP) else "UDP" if pkt.haslayer(scapy.UDP) else "ICMP" if pkt.haslayer(scapy.ICMP) else "OTHER") if SCAPY_AVAILABLE else "UNKNOWN"}
            try:
                self.result_q.put_nowait(result)
            except queue.Full:
                logging.debug("Result queue full, dropping packet result")
        except Exception:
            logging.exception("Error in analyze_and_queue")

    def _on_ips_block(self, rec):
        with self.lock:
            self.alerts.append({"time": rec.get("time"), "type": rec.get("type", "IPS_BLOCK"),
                "actor": rec.get("target", ""), "severity": rec.get("severity", "HIGH"), "size": 0})
            if rec.get("kind") == "ip":
                self.blocked_ips.add(rec.get("target", ""))

    def block_attacker(self, target, reason="", severity="HIGH", threat_type="IPS_BLOCK"):
        res = self._ips.block_attacker(target, reason=reason, severity=severity, threat_type=threat_type)
        if res.get("ok") and res.get("kind") == "ip":
            self.blocked_ips.add(target)
        return res

    def unblock_target(self, target):
        ok = self._ips.unblock_target(target)
        self.blocked_ips.discard(target)
        return ok

    def analyze(self, pkt):
        if not SCAPY_AVAILABLE: return "N/A", "#777", []
        threats = []; now = time.time(); size = len(pkt)
        cfg = load_config()
        with self.lock:
            self.packet_count += 1
            self.packet_stats["total"] += 1
            self.packet_stats["bytes"] += size
            # per-IP rate tracking (packets per second sliding window)
            if pkt.haslayer(scapy.IP):
                src = pkt[scapy.IP].src
                dq = self.ip_rate[src]
                dq.append(now)
                # remove old
                window = 2.0
                while dq and now - dq[0] > window:
                    dq.popleft()
                pps = len(dq)
                # simple high-rate detection
                cfg = load_config()
                pps_thresh = cfg.get("pps_thresh", 200)
                if pps >= pps_thresh:
                    threats.append(("HIGH_PPS", src, "HIGH"))
            if cfg.get("device_fingerprint_enabled", True) and pkt.haslayer(scapy.IP):
                src_fp = pkt[scapy.IP].src
                vend = lookup_vendor(self.arp_table.get(src_fp, "")) if self.arp_table.get(src_fp) else ""
                threats.extend(self._device_fp.analyze_packet(pkt, src_fp, vendor=vend, now=now))
            if pkt.haslayer(scapy.ARP):
                self.proto_counts["ARP"] += 1
                if pkt[scapy.ARP].op == 2:
                    ip_a = pkt[scapy.ARP].psrc; mac = pkt[scapy.ARP].hwsrc
                    if ip_a in self.arp_table and self.arp_table[ip_a] != mac:
                        threats.append(("ARP_SPOOF", ip_a, "CRITICAL"))
                    # store vendor information for discovered ARP hosts
                    try:
                        load_oui()
                        self.arp_table[ip_a] = mac
                    except Exception:
                        self.arp_table[ip_a] = mac

            if not pkt.haslayer(scapy.IP): return " SAFE", "#0F0", []
            src = pkt[scapy.IP].src; dst = pkt[scapy.IP].dst
            # try to attach vendor if present in arp table
            vendor = None
            try:
                mac = self.arp_table.get(src)
                if mac:
                    load_oui()
                    vendor = lookup_vendor(mac)
            except Exception:
                vendor = None
            if src in self.blocked_ips or self._ips.is_blocked(src):
                self.packet_stats["blocked"] += 1
                return "🚫 BLOCKED", "#800080", []
            if pkt.haslayer(scapy.TCP):
                self.proto_counts["TCP"] += 1
                flags = int(pkt[scapy.TCP].flags); dport = pkt[scapy.TCP].dport
                if (flags & 0x02) and not (flags & 0x10):
                    self.syn_track[src].append(now)
                    # keep only recent
                    self.syn_track[src] = deque([t for t in self.syn_track[src] if now-t < 2], maxlen=500)
                    if len(self.syn_track[src]) >= self.SIGS.get("SYN_FLOOD", {}).get("thresh", 100):
                        threats.append(("SYN_FLOOD", src, "CRITICAL"))
                self.port_scan_track[src].add(dport)
                if len(self.port_scan_track[src]) >= self.SIGS.get("PORT_SCAN", {}).get("thresh", 15):
                    threats.append(("PORT_SCAN", src, "HIGH"))
                if dport in (22, 3389, 21, 23):
                    key = f"bf_{src}_{dport}"
                    self.ip_ts[key].append(now)
                    self.ip_ts[key] = [t for t in self.ip_ts[key] if now-t < 30]
                    if len(self.ip_ts[key]) >= self.SIGS.get("BRUTE_FORCE", {}).get("thresh", 8):
                        threats.append(("BRUTE_FORCE", src, "HIGH"))
            elif pkt.haslayer(scapy.UDP):
                self.proto_counts["UDP"] += 1
                dport = pkt[scapy.UDP].dport; sport = pkt[scapy.UDP].sport
                if dport == 53 or sport == 53:
                    self.proto_counts["DNS"] += 1
                    self.dns_track[src].append(size)
                    if len(self.dns_track[src]) > 3:
                        self.dns_track[src] = self.dns_track[src][-10:]
                        if sum(self.dns_track[src]) > 3000:
                            threats.append(("DNS_TUNNEL", src, "HIGH"))
            elif pkt.haslayer(scapy.ICMP):
                self.proto_counts["ICMP"] += 1
                self.icmp_track[src].append(now)
                self.icmp_track[src] = [t for t in self.icmp_track[src] if now-t < 2]
                if len(self.icmp_track[src]) >= self.SIGS.get("ICMP_FLOOD", {}).get("thresh", 50):
                    threats.append(("ICMP_FLOOD", src, "MEDIUM"))
            else:
                self.proto_counts["OTHER"] += 1
            if size >= self.SIGS.get("DATA_EXFIL", {}).get("thresh", 8*1024):
                threats.append(("DATA_EXFIL", src, "CRITICAL"))
            app = self._identify_app(pkt)
            self.app_counts[app] += 1

            # ── ИСПРАВЛЕНИЕ: скользящее окно для графика "последние 60 сек" ──
            # Без этого LAN накапливается часами и YouTube не виден в топе.
            self._app_recent_ts.append((now, app))
            # Сдвигаем окно — убираем устаревшие записи
            while self._app_recent_ts and now - self._app_recent_ts[0][0] > self._APP_WINDOW:
                old_app = self._app_recent_ts.popleft()[1]
                if self.app_counts_recent[old_app] > 0:
                    self.app_counts_recent[old_app] -= 1
            self.app_counts_recent[app] += 1

            # ── ИСПРАВЛЕНИЕ: используем кешированный конфиг ──
            if cfg.get("auto_block") and threats:
                for ttype, actor, sev in threats:
                    if sev in ("CRITICAL", "HIGH") and actor not in self._ips.ignored:
                        self.block_attacker(actor, reason=ttype, severity=sev, threat_type=ttype)
            for ttype, actor, sev in threats:
                self._raise_alert(ttype, actor, sev, size)
                # persist alerts to DB async if available
                try:
                    db = get_db()
                    if db:
                        db.insert_alert({"time": datetime.now().strftime("%H:%M:%S"), "type": ttype, "actor": actor, "severity": sev, "size": size})
                except Exception:
                    pass
            if threats:
                self.threat_count += 1
                return f"⚠ {threats[0][0]}", "#FF3B5C", threats
            if pkt.haslayer(scapy.ICMP): return "● ICMP", "#00D4FF", []
            return " SAFE", "#00FF88", []

    def _identify_app(self, pkt):
        """
        Идентифицирует приложение по пакету.

        ИСПРАВЛЕНИЯ:
        1. YouTube/Google проверяется ПЕРВЫМ (раньше LAN) — мгновенное обнаружение
        2. Расширен список IP-диапазонов YouTube (10+ диапазонов вместо 1)
        3. LAN-трафик детализирован: роутер, DNS, DHCP, mDNS — отдельные категории
        4. HTTPS-порт 443 → проверяем последний известный dst для этого IP
        5. Используем sliding window: app_counts_recent — только последние 30 сек
        """
        if not SCAPY_AVAILABLE or not pkt.haslayer(scapy.IP):
            return "Unknown"

        src = pkt[scapy.IP].src
        dst = pkt[scapy.IP].dst

        # ── 1. YOUTUBE / GOOGLE VIDEO — приоритет #1, ДО проверки LAN ────────
        # Google использует множество диапазонов для видеострима.
        # Источник: Google ASN AS15169, AS36040 (YouTube CDN)
        YOUTUBE_PREFIXES = (
            "142.250.", "142.251.",           # Google Global (основной YouTube)
            "172.217.", "172.253.",            # Google Global
            "216.58.",  "216.239.",            # Google
            "74.125.",                          # Google (videos)
            "64.233.",                          # Google
            "209.85.",                          # Google TP (видео-чанки)
            "173.194.",                         # Google (стриминг)
            "34.64.",   "34.65.",   "34.66.",  # Google Cloud / YouTube CDN
            "34.96.",   "34.98.",   "34.100.", # Google Cloud
            "35.186.",  "35.190.",  "35.191.", # Google Cloud LB
            "66.102.",                          # Google
            "108.177.",                         # Google
            "199.36.",                          # Google APIs
        )
        # Отдельно Google-сервисы (не видео)
        GOOGLE_PREFIXES = (
            "8.8.8.8", "8.8.4.4",             # Google DNS
        )

        for pfx in YOUTUBE_PREFIXES:
            if dst.startswith(pfx) or src.startswith(pfx):
                # Пытаемся различить YouTube-видео от обычного Google
                if pkt.haslayer(scapy.TCP):
                    dport = pkt[scapy.TCP].dport
                    sport = pkt[scapy.TCP].sport
                    # Видео-чанки YouTube идут через HTTPS (443) большими пакетами
                    if (dport == 443 or sport == 443) and len(pkt) > 500:
                        return "🎥 YouTube"
                    if dport == 443 or sport == 443:
                        return "🎥 YouTube"
                if pkt.haslayer(scapy.UDP):
                    dport = pkt[scapy.UDP].dport
                    sport = pkt[scapy.UDP].sport
                    # QUIC (YouTube использует QUIC/HTTP3 на порту 443 UDP)
                    if dport == 443 or sport == 443:
                        return "🎥 YouTube"
                return "🔍 Google"

        # ── 2. ОСТАЛЬНЫЕ ВНЕШНИЕ СЕРВИСЫ ─────────────────────────────────────
        EXTERNAL_IP_MAP = [
            # Социальные сети
            ("31.13.",     "📘 Facebook"),
            ("157.240.",   "📘 Facebook"),
            ("179.60.",    "💬 WhatsApp"),
            ("3.33.",      "💬 WhatsApp"),    # AWS WhatsApp CDN

            # Мессенджеры
            ("91.108.",    "✈ Telegram"),
            ("149.154.",   "✈ Telegram"),
            ("95.161.",    "✈ Telegram"),

            # Видео/стриминг
            ("108.175.",   "🎬 Netflix"),
            ("23.246.",    "🎬 Netflix"),
            ("198.38.",    "🎬 Netflix"),
            ("170.114.",   "📹 Zoom"),
            ("162.255.",   "📹 Zoom"),
            ("52.202.",    "📹 Zoom"),

            # Microsoft
            ("13.107.",    "🪟 Microsoft"),
            ("52.112.",    "🪟 Teams"),
            ("40.96.",     "🪟 Microsoft"),
            ("40.112.",    "🪟 Microsoft"),
            ("20.190.",    "🪟 Microsoft"),

            # CDN
            ("104.16.",    "☁ Cloudflare"),
            ("104.17.",    "☁ Cloudflare"),
            ("104.18.",    "☁ Cloudflare"),
            ("104.19.",    "☁ Cloudflare"),
            ("104.20.",    "☁ Cloudflare"),
            ("151.101.",   "☁ Fastly CDN"),
            ("199.232.",   "☁ Fastly CDN"),
            ("143.204.",   "☁ Amazon CDN"),

            # Разработка
            ("140.82.",    "🐙 GitHub"),
            ("185.199.",   "🐙 GitHub"),

            # Amazon/AWS
            ("52.",        "☁ AWS"),
            ("54.",        "☁ AWS"),
            ("18.",        "☁ AWS"),
            ("3.",         "☁ AWS"),

            # Apple
            ("17.",        "🍎 Apple"),
            ("63.92.",     "🍎 Apple"),

            # Яндекс
            ("77.88.",     "🔷 Yandex"),
            ("213.180.",   "🔷 Yandex"),

            # VK
            ("87.240.",    "🔵 VKontakte"),
            ("93.186.",    "🔵 VKontakte"),

            # TikTok / ByteDance
            ("69.171.",    "🎵 TikTok"),
            ("128.242.",   "🎵 TikTok"),

            # Kaspi (Казахстан)
            ("92.46.",     "💳 Kaspi"),
            ("178.89.",    "📡 Beeline KZ"),
            ("91.185.",    "📱 Tele2 KZ"),
        ]

        for pfx, name in EXTERNAL_IP_MAP:
            if dst.startswith(pfx) or src.startswith(pfx):
                return name

        # ── 3. DNS-серверы ────────────────────────────────────────────────────
        DNS_SERVERS = {
            "8.8.8.8": "🔎 Google DNS", "8.8.4.4": "🔎 Google DNS",
            "1.1.1.1": "🔎 Cloudflare DNS", "1.0.0.1": "🔎 Cloudflare DNS",
            "9.9.9.9": "🔎 Quad9 DNS",
            "208.67.222.222": "🔎 OpenDNS",
        }
        for dns_ip, dns_name in DNS_SERVERS.items():
            if dst == dns_ip or src == dns_ip:
                return dns_name

        # ── 4. LAN-ТРАФИК — детализированный ─────────────────────────────────
        # Определяем тип LAN-узла вместо общего "LAN"
        def _is_lan(ip):
            return (ip.startswith("192.168.") or ip.startswith("10.") or
                    ip.startswith("172.16.") or ip.startswith("172.17.") or
                    ip.startswith("172.18.") or ip.startswith("172.19.") or
                    ip.startswith("172.2") or ip.startswith("172.3") or
                    ip == "127.0.0.1" or ip.startswith("169.254."))

        src_lan = _is_lan(src)
        dst_lan = _is_lan(dst)

        if src_lan or dst_lan:
            # Broadcast / multicast — системные
            if dst in ("255.255.255.255", "192.168.0.255", "192.168.1.255"):
                return "📢 LAN Broadcast"
            if dst.startswith("224.") or dst.startswith("239."):
                return "📡 LAN Multicast"
            if dst == "127.0.0.1" or src == "127.0.0.1":
                return "🖥 Localhost"

            # Роутер (первые адреса подсети)
            router_candidates = set()
            for base in ("192.168.0.", "192.168.1.", "10.0.0.", "10.0.1."):
                router_candidates.add(base + "1")
                router_candidates.add(base + "254")
            if src in router_candidates or dst in router_candidates:
                # Смотрим порт чтобы понять зачем идём к роутеру
                if pkt.haslayer(scapy.UDP):
                    dp = pkt[scapy.UDP].dport; sp = pkt[scapy.UDP].sport
                    if dp == 53 or sp == 53:   return "🔎 Router DNS"
                    if dp == 67 or dp == 68:   return "🔧 DHCP"
                    if dp == 123:              return "🕐 NTP"
                if pkt.haslayer(scapy.TCP):
                    dp = pkt[scapy.TCP].dport
                    if dp == 80:               return "🌐 Router HTTP"
                    if dp in (443, 8443):      return "🔒 Router HTTPS"
                return "🌐 Router"

            # mDNS / Bonjour (224.0.0.251 порт 5353)
            if dst == "224.0.0.251" or (pkt.haslayer(scapy.UDP) and
               (pkt[scapy.UDP].dport == 5353 or pkt[scapy.UDP].sport == 5353)):
                return "📡 mDNS"

            # SSDP (UPnP устройства — Smart TV, Chromecast)
            if dst == "239.255.255.250" or (pkt.haslayer(scapy.UDP) and
               pkt[scapy.UDP].dport == 1900):
                return "📺 SSDP/UPnP"

            # DHCP
            if pkt.haslayer(scapy.UDP):
                dp = pkt[scapy.UDP].dport; sp = pkt[scapy.UDP].sport
                if dp in (67, 68) or sp in (67, 68): return "🔧 DHCP"
                if dp == 5353 or sp == 5353:          return "📡 mDNS"
                if dp == 137 or dp == 138:            return "🖥 NetBIOS"

            # SMB / Windows File Share
            if pkt.haslayer(scapy.TCP):
                dp = pkt[scapy.TCP].dport
                if dp == 445 or dp == 139:   return "🗂 SMB Share"
                if dp == 3389:               return "🖥 RDP"
                if dp == 22:                 return "🔑 SSH"
                if dp == 80:                 return "🌐 LAN HTTP"
                if dp == 443:                return "🔒 LAN HTTPS"
                if dp == 8080:               return "🌐 LAN HTTP-Alt"

            return "🏠 LAN"

        # ── 5. ВНЕШНИЙ ТРАФИК — порт как последний вариант ───────────────────
        PORT_MAP = {
            443:  "🔒 HTTPS",  80:   "🌐 HTTP",    8080: "🌐 HTTP-Alt",
            22:   "🔑 SSH",    23:   "⚠ Telnet",   21:   "📂 FTP",
            25:   "📧 SMTP",   587:  "📧 SMTP-TLS", 993:  "📧 IMAPS",
            3389: "🖥 RDP",    5900: "🖥 VNC",      3306: "🗄 MySQL",
            5432: "🗄 PgSQL",  1433: "🗄 MSSQL",    27017:"🗄 MongoDB",
            445:  "🗂 SMB",    6881: "📥 BitTorrent",123: "🕐 NTP",
        }
        if pkt.haslayer(scapy.TCP):
            dp = pkt[scapy.TCP].dport; sp = pkt[scapy.TCP].sport
            if dp in PORT_MAP: return PORT_MAP[dp]
            if sp in PORT_MAP: return PORT_MAP[sp]
        if pkt.haslayer(scapy.UDP):
            dp = pkt[scapy.UDP].dport; sp = pkt[scapy.UDP].sport
            if dp == 53 or sp == 53: return "🔎 DNS"
            if dp in PORT_MAP: return PORT_MAP[dp]
            if sp in PORT_MAP: return PORT_MAP[sp]

        return "General"

    def _raise_alert(self, atype, actor, sev, size):
        a = {"time": datetime.now().strftime("%H:%M:%S"), "type": atype,
             "actor": actor, "severity": sev, "size": size}
        self.alerts.append(a)
        if len(self.alerts) > 2000: self.alerts = self.alerts[-1000:]
        for cb in self.alert_callbacks:
            try: cb(a)
            except Exception:
                logging.exception("Alert callback failed")
        target_bot = self.bot or self._tg_bot
        # If actor is whitelisted, skip sending Telegram notifications
        try:
            if actor and is_whitelisted(actor):
                logging.info("[Whitelist] actor %s is whitelisted; skipping notifications", actor)
                return
        except Exception:
            pass
        if target_bot and sev in ("CRITICAL", "HIGH"):
            threading.Thread(target=target_bot.send_alert, args=(a,), daemon=True).start()

    def block_ip(self, ip, reason="", severity="HIGH"):
        self.block_attacker(ip, reason=reason or "Manual block", severity=severity, threat_type="MANUAL_BLOCK")

    def unblock_ip(self, ip):
        self.unblock_target(ip)

    def block_mac(self, mac, reason="", severity="CRITICAL"):
        return self.block_attacker(mac, reason=reason, threat_type="WIFI_BLOCK", severity=severity)

    def _add_firewall_rule(self, ip):
        self._ips.block_attacker(ip, use_firewall=True)

    def _proc_loop(self):
        while self._proc_running:
            try:
                for _ in range(50):
                    try:
                        item = self.result_q.get_nowait()
                    except queue.Empty:
                        break

                    if not isinstance(item, dict):
                        continue

                    if item.get("wifi_threat") and not item.get("_display_only"):
                        now_str = datetime.now().strftime("%H:%M:%S")
                        fake_pkt_data = {
                            "time":    now_str,
                            "src":     item.get("wifi_actor", "00:00:00:00:00:00"),
                            "dst":     item.get("wifi_target", "BROADCAST"),
                            "proto":   "802.11",
                            "app":     f"📡 {item.get('wifi_type', 'WIFI')}",
                            "size":    item.get("size", 0),
                            "status":  item.get("status", "⚠ ATTACK"),
                            "threats": [item.get("wifi_msg", "")],
                            "vendor":  item.get("vendor", "Unknown"),
                        }
                        with self.lock:
                            self.packet_stats["total"] += 1
                            self.app_counts[fake_pkt_data["app"]] += 1
                            self.proto_counts["802.11"] += 1
                            alert_rec = {
                                "time":     now_str,
                                "type":     item.get("wifi_type", "WIFI"),
                                "actor":    item.get("wifi_actor", ""),
                                "severity": item.get("wifi_sev", "HIGH"),
                                "size":     item.get("size", 0),
                            }
                            self.alerts.append(alert_rec)
                            if len(self.alerts) > 2000:
                                self.alerts = self.alerts[-1000:]
                            for cb in self.alert_callbacks:
                                try:
                                    cb(alert_rec)
                                except Exception:
                                    pass
                        try:
                            db = get_db()
                            if db:
                                db.insert_packet(fake_pkt_data)
                        except Exception:
                            pass
                        with self.lock:
                            for cb in self._packet_callbacks:
                                try:
                                    cb(fake_pkt_data)
                                except Exception:
                                    pass
                        display_item = dict(item)
                        display_item["_display_only"] = True
                        try:
                            self.result_q.put_nowait(display_item)
                        except queue.Full:
                            pass
            except Exception:
                logging.exception("Error in proc_loop")
            time.sleep(0.05)

    def get_stats(self):
        with self.lock:
            # Отдаём app_counts_recent (скользящее окно 60 сек) для графика —
            # так YouTube появится в топе СРАЗУ как только открыт, а LAN
            # не будет доминировать накопленной статистикой за часы работы.
            return (dict(self.packet_stats),
                    dict(self.proto_counts),
                    dict(self.app_counts_recent) if self.app_counts_recent
                    else dict(self.app_counts))

    def get_snapshot(self):
        with self.lock:
            now = datetime.now()
            recent_alerts = []
            for a in self.alerts[-200:]:
                try:
                    at = datetime.strptime(a["time"], "%H:%M:%S").replace(
                        year=now.year, month=now.month, day=now.day)
                    if abs((now - at).total_seconds()) < 60:
                        recent_alerts.append(a)
                except Exception:
                    logging.exception("Failed to parse alert time")

            top_attackers = collections.Counter(
                a["actor"] for a in recent_alerts
            ).most_common(5)

            wifi_stats, risk = {}, {}
            if getattr(self, "_wifi_monitor", None):
                try:
                    wifi_stats = self._wifi_monitor.get_stats()
                    from core.wifi_risk import compute_risk_score
                    risk = compute_risk_score(wifi_stats, recent_alerts,
                        self._wifi_monitor.get_heatmap() if hasattr(self._wifi_monitor, "get_heatmap") else [])
                except Exception:
                    pass
            return {
                "mode": "SIMULATION" if getattr(self, '_demo', False) else "LIVE",
                "ips_mode": "IPS" if load_config().get("auto_block") else "IDS",
                "wifi_risk": risk, "wifi_stats": wifi_stats,
                "total_packets": self.packet_stats.get("total", 0),
                "total_bytes":   self.packet_stats.get("bytes", 0),
                "blocked_pkts":  self.packet_stats.get("blocked", 0),
                "threat_events": self.threat_count,
                "blocked_ips":   list(self.blocked_ips),
                "protocols":     dict(self.proto_counts),
                "top_apps":      dict(sorted(
                    (self.app_counts_recent if self.app_counts_recent else self.app_counts).items(),
                    key=lambda x: x[1], reverse=True)[:8]),
                "alerts_last60s": [
                    {"time": a["time"], "type": a["type"],
                     "actor": a["actor"], "sev": a["severity"]}
                    for a in recent_alerts[-20:]
                ],
                "top_attackers": [{"ip": ip, "alerts": n} for ip, n in top_attackers],
                "arp_hosts":     len(self.arp_table),
                "active_conns":  len(self.proc_map),
                "security": {"ips": self._ips.get_snapshot(), "devices": self._device_fp.get_all()[:20],
                             "plugins": self._plugins},
            }

    def reload_sigs(self):
        cfg = load_config(); self.SIGS = _get_sigs_from_cfg(cfg)

    def shutdown(self):
        try:
            if getattr(self, '_wifi_monitor', None) is not None:
                try: self._wifi_monitor.stop()
                except Exception:
                    logging.exception("Failed to stop WiFiMonitor during shutdown")
        except Exception:
            logging.exception("Error checking WiFiMonitor during shutdown")
        try:
            if getattr(self, '_demo_gen', None) is not None:
                try: self._demo_gen.stop()
                except Exception:
                    logging.exception("Failed to stop demo generator during shutdown")
        except Exception:
            logging.exception("Error checking demo generator during shutdown")
        try:
            self._proc_running = False
            if self._proc_thread and self._proc_thread.is_alive():
                self._proc_thread.join(timeout=1.0)
        except Exception:
            logging.exception("Error stopping proc thread")
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            logging.exception("Error shutting down executor")

    def _init_telegram(self):
        try:
            from utils.config import load_config
            cfg = load_config()
            token = cfg.get("tg_token", "")
            chat_id = cfg.get("tg_chat_id", "")
            if token and chat_id:
                from core.telegram_bot import TelegramBot
                self._tg_bot = TelegramBot(token=token, chat_id=chat_id, engine=self)
                self._tg_bot.start()
                logging.info("[TelegramBot] Started")
        except Exception:
            logging.exception("[TelegramBot] init failed")

    def reload_telegram(self):
        try:
            if self.bot:
                self.bot.stop()
                self.bot = None
                from utils.config import load_config
                cfg = load_config()
                token = cfg.get("tg_token", "")
                chat_id = cfg.get("tg_chat_id", "")
                if token and chat_id:
                    from core.telegram_bot import TelegramBot
                    self.bot = TelegramBot(token=token, chat_id=chat_id, engine=self)
                    self.bot.start()
                    return
            if self._tg_bot:
                self._tg_bot.stop()
                self._tg_bot = None
        except Exception:
            pass
        if self.bot is None:
            self._init_telegram()