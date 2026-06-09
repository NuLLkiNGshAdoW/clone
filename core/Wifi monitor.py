"""
core.wifi_monitor — 802.11 Deep Packet Inspection Module
=========================================================
Kismet-style passive radio surveillance for SOC Sentinel.

Detects:
  • Deauth Flood (mass deauthentication attacks)
  • Evil Twin AP (same SSID, different BSSID / anomalous RSSI)
  • Beacon Flood (hundreds of fake APs)
  • Rogue AP Fingerprinting (MAC OUI vs device type mismatch)
  • Probe Request harvesting (who's looking for what network)
  • PMKID / EAPOL Handshake sniffing (WPA crack attempts)
  • Management frame anomalies

Architecture:
  - WiFiMonitor runs in its own daemon thread (never blocks GUI)
  - All results are injected into ThreatEngine via _raise_alert()
    and the engine's result_q — identical path to IP threats
  - Uses scapy RadioTap + Dot11 layers (monitor-mode adapter required)
  - Trusted device DB is loaded from wifi_trusted.json (auto-created)
  - Rate Limiting (debounce) prevents _alert() flood during stress tests:
    each (alert_type, actor_mac) pair fires at most once per ALERT_DEBOUNCE_SECS,
    while raw counters (deauths_seen etc.) still increment on every packet.

Usage:
    from core.wifi_monitor import WiFiMonitor
    mon = WiFiMonitor(engine=threat_engine_instance)
    mon.start(iface="wlan0mon")   # monitor-mode interface
    ...
    mon.stop()
"""

from __future__ import annotations

import threading
import time
import json
import logging
import collections
import queue
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Optional scapy import (same pattern as ThreatEngine) ────────────────────
try:
    import scapy.all as scapy
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoReq,
        Dot11Elt, RadioTap,
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    logging.warning("[WiFiMonitor] scapy not available — 802.11 analysis disabled")

# ── Constants ────────────────────────────────────────────────────────────────
TRUSTED_DB_PATH = Path("wifi_trusted.json")

# Deauth reason codes that are suspicious (mass kick-off)
DEAUTH_SUSPICIOUS_REASONS = {1, 2, 3, 4, 6, 7}  # reason codes from 802.11 spec

# RSSI delta (dBm) that triggers Evil Twin signal anomaly
EVIL_TWIN_RSSI_DELTA = 20   # ±20 dBm sudden change is suspicious

# Thresholds
DEAUTH_FLOOD_THRESH   = 10   # deauths per 5 s from one source → alert
BEACON_FLOOD_THRESH   = 50   # unique SSIDs per 10 s → alert
PROBE_LOG_MAX         = 500  # max probe records kept in memory

# ── Rate Limiting (debounce) constant ────────────────────────────────────────
# Heavy _alert() calls (disk I/O, DB write, engine lock) are suppressed if the
# same (alert_type, actor_mac) pair fired within this window.
# This prevents GUI freeze during mass deauth / beacon / auth floods.
ALERT_DEBOUNCE_SECS: float = 15.0  # seconds between repeated alerts per actor
# Raised from 4.5 → 15.0: aireplay-ng sends deauth bursts every ~2 s;
# 4.5 s was not enough to suppress the flood and caused GUI freeze.


# ── Data classes ─────────────────────────────────────────────────────────────
@dataclass
class APRecord:
    """Represents a discovered Access Point."""
    ssid:       str
    bssid:      str
    channel:    int
    rssi:       int          # last known signal (dBm)
    vendor:     str
    first_seen: str
    last_seen:  str
    beacon_count: int = 0
    is_rogue:   bool = False
    notes:      List[str] = field(default_factory=list)


@dataclass
class ProbeRecord:
    """A device probing for a specific SSID."""
    client_mac: str
    ssid:       str          # empty string = wildcard probe
    vendor:     str
    ts:         str
    rssi:       int


@dataclass
class DeauthRecord:
    src:    str
    dst:    str
    reason: int
    ts:     float


# ── Trusted device database ───────────────────────────────────────────────────
class TrustedDeviceDB:
    """
    JSON-backed store of known-good devices.
    Each entry: { mac: { "alias": str, "vendor": str, "trusted": bool } }
    """
    def __init__(self, path: Path = TRUSTED_DB_PATH):
        self.path = path
        self._db: Dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._db = json.load(f)
            except Exception:
                self._db = {}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._db, f, indent=2, ensure_ascii=False)
        except Exception:
            logging.exception("[TrustedDB] Failed to save")

    def trust(self, mac: str, alias: str = "", vendor: str = ""):
        mac = mac.upper()
        self._db[mac] = {"alias": alias, "vendor": vendor, "trusted": True}
        self.save()

    def distrust(self, mac: str):
        self._db.pop(mac.upper(), None)
        self.save()

    def is_trusted(self, mac: str) -> bool:
        return self._db.get(mac.upper(), {}).get("trusted", False)

    def get(self, mac: str) -> Optional[dict]:
        return self._db.get(mac.upper())

    def all_entries(self) -> dict:
        return dict(self._db)


# ── OUI vendor lookup (reuses logic compatible with threat_engine) ────────────
_OUI_MINI = {
    # Apple
    "A4:5E:60": "Apple", "F0:18:98": "Apple", "3C:15:C2": "Apple",
    "DC:2B:2A": "Apple", "08:66:98": "Apple", "14:5A:05": "Apple",
    "78:4F:43": "Apple", "A8:51:AB": "Apple", "00:17:F2": "Apple",
    # Samsung
    "44:38:39": "Samsung", "8C:BE:BE": "Samsung", "B8:F8:83": "Samsung",
    "18:89:5B": "Samsung", "10:D3:8A": "Samsung",
    # Xiaomi
    "3C:5A:B4": "Xiaomi", "F4:F5:DB": "Xiaomi", "28:6C:07": "Xiaomi",
    # Cisco
    "00:1A:2B": "Cisco", "00:0B:5F": "Cisco", "84:78:AC": "Cisco",
    # Intel (Wi-Fi chipsets)
    "F0:D1:A9": "Intel", "AC:FD:CE": "Intel", "A4:C3:F0": "Intel",
    "00:21:6A": "Intel", "40:A8:F0": "Intel",
    # Realtek
    "00:E0:4C": "Realtek", "90:2B:34": "Realtek",
    # Qualcomm / Atheros
    "00:03:7F": "Atheros", "00:1F:1F": "Atheros",
    # TP-Link (routers)
    "50:C7:BF": "TP-Link", "A0:F3:C1": "TP-Link", "18:D6:C7": "TP-Link",
    "EC:08:6B": "TP-Link", "54:AF:97": "TP-Link",
    # ASUS
    "AC:9E:17": "ASUS", "04:92:26": "ASUS", "10:7B:EF": "ASUS",
    # D-Link
    "B0:C5:54": "D-Link", "F0:7D:68": "D-Link", "C8:BE:19": "D-Link",
    # Huawei
    "48:FD:8E": "Huawei", "58:2A:F7": "Huawei", "00:18:82": "Huawei",
    # Mikrotik
    "00:0C:42": "Mikrotik", "D4:CA:6D": "Mikrotik", "CC:2D:E0": "Mikrotik",
    # Alfa (hacker / pentest adapters — flag these)
    "00:C0:CA": "Alfa Network", "00:1A:EF": "Alfa Network",
    # Pineapple / Hak5 (pentest tools)
    "2C:C5:46": "Hak5",
}

# Device "type" heuristics: which vendors make what
VENDOR_DEVICE_TYPES: Dict[str, Set[str]] = {
    "Apple":    {"smartphone", "laptop", "tablet", "desktop"},
    "Samsung":  {"smartphone", "tablet", "tv", "laptop"},
    "Xiaomi":   {"smartphone", "tablet", "router", "iot"},
    "Intel":    {"laptop", "desktop"},       # Intel makes Wi-Fi chips, not phones
    "Realtek":  {"laptop", "usb_dongle"},
    "Atheros":  {"laptop", "router", "usb_dongle"},
    "TP-Link":  {"router", "ap", "repeater"},
    "ASUS":     {"router", "laptop", "ap"},
    "D-Link":   {"router", "ap"},
    "Huawei":   {"smartphone", "router", "ap"},
    "Mikrotik": {"router", "ap"},
    "Alfa Network": {"usb_dongle", "pentest"},
    "Hak5":     {"pentest"},
}


def _oui_vendor(mac: str) -> str:
    """Look up vendor from MAC OUI (first 3 bytes)."""
    if not mac:
        return "Unknown"
    mac = mac.upper().replace("-", ":").strip()
    parts = mac.split(":")
    if len(parts) < 3:
        return "Unknown"
    key = ":".join(parts[:3])
    return _OUI_MINI.get(key, "Unknown")


def _is_pentest_vendor(vendor: str) -> bool:
    """Return True if vendor is associated with pentest / rogue hardware."""
    return vendor in {"Alfa Network", "Hak5"}


def _extract_rssi(pkt) -> int:
    """Extract RSSI from RadioTap header (-100 if unavailable)."""
    if not SCAPY_AVAILABLE:
        return -100
    try:
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            # Scapy exposes dBm_AntSignal on newer builds
            if hasattr(rt, "dBm_AntSignal"):
                return int(rt.dBm_AntSignal)
    except Exception:
        pass
    return -100


def _extract_channel(pkt) -> int:
    """Extract Wi-Fi channel from RadioTap or Dot11Elt."""
    if not SCAPY_AVAILABLE:
        return 0
    try:
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            if hasattr(rt, "Channel") and rt.Channel:
                # Convert frequency to channel
                freq = int(rt.Channel)
                if 2412 <= freq <= 2484:
                    return (freq - 2407) // 5
                if 5170 <= freq <= 5825:
                    return (freq - 5000) // 5
    except Exception:
        pass
    return 0


def _extract_ssid(pkt) -> str:
    """Extract SSID string from Dot11Elt (ID=0)."""
    if not SCAPY_AVAILABLE:
        return ""
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                raw = elt.info
                if isinstance(raw, bytes):
                    return raw.decode("utf-8", errors="replace").strip("\x00")
                return str(raw).strip("\x00")
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, "payload") else None
    except Exception:
        pass
    return ""


# ── Main monitor class ────────────────────────────────────────────────────────
class WiFiMonitor:
    """
    Passive 802.11 radio surveillance module.

    Emulates Kismet's core detection capabilities:
      1. AP database with Evil Twin detection
      2. Deauth flood detection (per-source rate limiting)
      3. Beacon flood detection (SSID cardinality in time window)
      4. Probe request harvesting
      5. Device fingerprinting (OUI vs claimed device type)
      6. Rogue / pentest adapter detection

    Rate Limiting (debounce):
      _last_alert_time[(atype, actor)] tracks when _alert() was last fired
      for each unique threat+actor pair. The heavy _alert() path (disk I/O,
      DB write, engine lock) is skipped if the same pair fired within
      ALERT_DEBOUNCE_SECS. Raw packet counters (deauths_seen etc.) are
      always updated so the UI statistics remain accurate in real time.
    """

    def __init__(self, engine=None):
        """
        Parameters
        ----------
        engine : ThreatEngine instance (optional)
            If provided, WiFiMonitor injects alerts via engine._raise_alert()
            and puts Wi-Fi packet results onto engine.result_q.
        """
        self.engine = engine
        self.trusted_db = TrustedDeviceDB()

        # ── State tables ──────────────────────────────────────────────────
        # BSSID → APRecord
        self._aps: Dict[str, APRecord] = {}

        # SSID → set of BSSIDs (Evil Twin: one SSID, many BSSIDs)
        self._ssid_bssid_map: Dict[str, Set[str]] = collections.defaultdict(set)

        # source MAC → deque of timestamps (Deauth flood tracking)
        self._deauth_track: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=200)
        )

        # Beacon flood: SSID set in rolling 10-second window
        self._beacon_ssids_window: collections.deque = collections.deque()
        self._beacon_window_secs = 10.0

        # Probe requests log
        self._probes: List[ProbeRecord] = []

        # PMKID / EAPOL tracking: src_mac → list[timestamp]
        self._eapol_track: Dict[str, list] = collections.defaultdict(list)

        # PPS tracking for management frames
        self._mgmt_pps_track: collections.deque = collections.deque(maxlen=2000)

        # Thread control
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._iface: str = ""

        self._lock = threading.Lock()

        # ── Rate Limiting: debounce table ─────────────────────────────────
        # Key: (alert_type: str, actor_mac: str) → last fire timestamp (float)
        # Prevents _alert() from being called hundreds of times per second
        # during floods, which would cause I/O bottleneck and GUI freeze.
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

        # Statistics exposed to UI
        self.stats = {
            "aps_seen":        0,
            "probes_seen":     0,
            "deauths_seen":    0,
            "evil_twins":      0,
            "rogue_aps":       0,
            "mgmt_pps":        0,
        }

        logging.info("[WiFiMonitor] Initialized (scapy=%s)", SCAPY_AVAILABLE)

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, iface: str):
        """Start capturing on monitor-mode interface `iface`."""
        if not SCAPY_AVAILABLE:
            logging.error("[WiFiMonitor] Cannot start — scapy unavailable")
            return
        if self._running:
            self.stop()
        self._iface = iface
        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="wifi_monitor"
        )
        self._thread.start()
        logging.info("[WiFiMonitor] Started on %s", iface)

    def stop(self):
        """Gracefully stop the capture loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logging.info("[WiFiMonitor] Stopped")

    def get_aps(self) -> List[dict]:
        """Return list of AP records as dicts (thread-safe)."""
        with self._lock:
            return [asdict(ap) for ap in self._aps.values()]

    def get_probes(self, limit: int = 100) -> List[dict]:
        """Return recent probe requests (thread-safe)."""
        with self._lock:
            return [asdict(p) for p in self._probes[-limit:]]

    def get_stats(self) -> dict:
        """Return current monitoring statistics."""
        with self._lock:
            return dict(self.stats)

    def trust_device(self, mac: str, alias: str = ""):
        """Mark a device as trusted."""
        vendor = _oui_vendor(mac)
        self.trusted_db.trust(mac, alias=alias, vendor=vendor)
        logging.info("[WiFiMonitor] Trusted: %s (%s)", mac, alias)

    def get_trusted_devices(self) -> dict:
        return self.trusted_db.all_entries()

    # ── Capture loop ──────────────────────────────────────────────────────────

    def _capture_loop(self):
        """Main background capture thread — never blocks the GUI."""
        logging.info("[WiFiMonitor] Capture loop started on %s", self._iface)
        while self._running:
            try:
                scapy.sniff(
                    iface=self._iface,
                    prn=self._handle_frame,
                    store=False,
                    timeout=2,
                    # Only capture management (type=0) and data frames relevant to 802.11
                )
            except OSError as e:
                logging.error("[WiFiMonitor] OSError: %s", e)
                time.sleep(3)
            except Exception as e:
                logging.error("[WiFiMonitor] Capture error: %s", e)
                time.sleep(3)
        logging.info("[WiFiMonitor] Capture loop ended")

    # ── Frame dispatcher ──────────────────────────────────────────────────────

    def _handle_frame(self, pkt):
        """Dispatch each 802.11 frame to the appropriate handler."""
        if not pkt.haslayer(Dot11):
            return

        # Track management PPS for chart integration
        now = time.time()
        with self._lock:
            self._mgmt_pps_track.append(now)
            # Prune old timestamps (>2 s)
            while self._mgmt_pps_track and now - self._mgmt_pps_track[0] > 2.0:
                self._mgmt_pps_track.popleft()
            self.stats["mgmt_pps"] = len(self._mgmt_pps_track) // 2  # per-second avg

        dot11 = pkt[Dot11]
        frame_type    = dot11.type     # 0=Management, 1=Control, 2=Data
        frame_subtype = dot11.subtype

        # Management frames (type=0)
        if frame_type == 0:
            if frame_subtype in (8,):           # Beacon
                self._on_beacon(pkt)
            elif frame_subtype in (4, 5):        # Probe Request / Response
                self._on_probe(pkt)
            elif frame_subtype in (12,):         # Deauthentication
                self._on_deauth(pkt)
            elif frame_subtype in (10,):         # Disassociation
                self._on_disassoc(pkt)
            elif frame_subtype in (11,):         # Authentication
                self._on_auth(pkt)

        # Data frames — check for EAPOL (WPA handshake)
        if frame_type == 2:
            self._on_data(pkt)

    # ── Rate limiting helper ──────────────────────────────────────────────────

    def _is_debounced(self, atype: str, actor: str, now: float) -> bool:
        """
        Return True if this (atype, actor) alert fired too recently and should
        be suppressed (debounced). Updates _last_alert_time if allowed.

        MUST be called inside self._lock to be thread-safe.

        Design rationale:
          During a mass deauth flood, aireplay-ng sends hundreds of frames/sec.
          Without debouncing, every frame triggers _alert(), which calls
          logging.warning() (disk I/O), db.insert_alert() (DB write), and
          acquires engine.lock (contention). This serializes the capture thread
          with the GUI event loop — causing the freeze we are fixing.

          With debouncing, the first packet of a burst fires _alert() normally;
          all subsequent packets within ALERT_DEBOUNCE_SECS are counted in
          the raw statistics but skip the heavy I/O path entirely.
        """
        key = (atype, actor)
        last = self._last_alert_time.get(key, 0.0)
        if now - last < ALERT_DEBOUNCE_SECS:
            return True   # suppressed — too soon
        self._last_alert_time[key] = now
        return False      # allowed — update timestamp and proceed

    # ── Beacon handler ────────────────────────────────────────────────────────

    def _on_beacon(self, pkt):
        """
        Process Beacon frames.
        Detects: new APs, Evil Twin, Beacon Flood, rogue adapters.
        """
        dot11  = pkt[Dot11]
        bssid  = dot11.addr3 or dot11.addr2 or ""
        ssid   = _extract_ssid(pkt)
        rssi   = _extract_rssi(pkt)
        chan   = _extract_channel(pkt)
        vendor = _oui_vendor(bssid)
        ts     = datetime.now().strftime("%H:%M:%S")
        now    = time.time()

        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            return

        with self._lock:
            # ── 1. Update AP database ─────────────────────────────────────
            if bssid not in self._aps:
                ap = APRecord(
                    ssid=ssid, bssid=bssid, channel=chan,
                    rssi=rssi, vendor=vendor,
                    first_seen=ts, last_seen=ts, beacon_count=1
                )
                self._aps[bssid] = ap
                self.stats["aps_seen"] += 1

                # ── 2. Rogue AP: pentest adapter vendor ───────────────────
                if _is_pentest_vendor(vendor):
                    ap.is_rogue = True
                    ap.notes.append(f"⚠ Pentest vendor: {vendor}")
                    # Rate limit: rogue APs are one-off discoveries, no debounce needed
                    self._alert(
                        atype="ROGUE_AP",
                        actor=bssid,
                        sev="HIGH",
                        size=len(pkt),
                        detail=f"Pentest adapter detected ({vendor}) broadcasting '{ssid}'"
                    )
                    self.stats["rogue_aps"] += 1

                # ── 3. Evil Twin: same SSID, different BSSID ─────────────
                if ssid:
                    self._ssid_bssid_map[ssid].add(bssid)
                    known_bssids = self._ssid_bssid_map[ssid]
                    if len(known_bssids) > 1:
                        original = next(iter(known_bssids - {bssid}))
                        orig_vendor = _oui_vendor(original)
                        # Rate limit: Evil Twin alert per rogue BSSID, not per beacon frame
                        if not self._is_debounced("EVIL_TWIN", bssid, now):
                            self._alert(
                                atype="EVIL_TWIN",
                                actor=bssid,
                                sev="CRITICAL",
                                size=len(pkt),
                                detail=(
                                    f"Evil Twin: SSID '{ssid}' has multiple BSSIDs! "
                                    f"Original={original} ({orig_vendor}), "
                                    f"Rogue={bssid} ({vendor})"
                                )
                            )
                        ap.is_rogue = True
                        ap.notes.append(f"⚠ Evil Twin of {original}")
                        self.stats["evil_twins"] += 1
            else:
                ap = self._aps[bssid]
                ap.last_seen  = ts
                ap.beacon_count += 1

                # ── 4. Evil Twin RSSI anomaly detection ───────────────────
                # Legitimate APs have stable RSSI; a closer rogue spikes suddenly
                if abs(rssi - ap.rssi) >= EVIL_TWIN_RSSI_DELTA and ap.rssi != -100:
                    # Rate limit: RSSI anomaly per AP — changes settle in seconds
                    if not self._is_debounced("RSSI_ANOMALY", bssid, now):
                        self._alert(
                            atype="RSSI_ANOMALY",
                            actor=bssid,
                            sev="HIGH",
                            size=len(pkt),
                            detail=(
                                f"AP '{ssid}' ({bssid}) RSSI jumped "
                                f"{ap.rssi} → {rssi} dBm  (Δ={rssi - ap.rssi:+d} dBm). "
                                f"Possible Evil Twin or AP relocation."
                            )
                        )
                ap.rssi    = rssi
                ap.channel = chan

            # ── 5. Beacon Flood detection ─────────────────────────────────
            self._beacon_ssids_window.append((now, ssid))
            # Prune old entries
            while (self._beacon_ssids_window and
                   now - self._beacon_ssids_window[0][0] > self._beacon_window_secs):
                self._beacon_ssids_window.popleft()

            unique_ssids = len({s for _, s in self._beacon_ssids_window})
            if unique_ssids >= BEACON_FLOOD_THRESH:
                # Rate limit: BEACON_FLOOD fires at most once per debounce window.
                # bssid here is the last seen flooder — a representative actor.
                # The counter still grows on every beacon frame above.
                if not self._is_debounced("BEACON_FLOOD", bssid, now):
                    self._alert(
                        atype="BEACON_FLOOD",
                        actor=bssid,
                        sev="HIGH",
                        size=len(pkt),
                        detail=(
                            f"Beacon Flood: {unique_ssids} unique SSIDs in "
                            f"last {self._beacon_window_secs:.0f}s. "
                            f"Possible rogue AP tool (mdk3, hostapd-wpe)."
                        )
                    )

    # ── Probe request handler ─────────────────────────────────────────────────

    def _on_probe(self, pkt):
        """
        Process Probe Request / Response frames.
        Records which device is looking for which SSID.
        Detects wildcard probers (privacy risk / reconnaissance).
        """
        dot11 = pkt[Dot11]
        is_request = (dot11.subtype == 4)
        if not is_request:
            return   # we only log requests for now

        client_mac = dot11.addr2 or ""
        ssid       = _extract_ssid(pkt)
        rssi       = _extract_rssi(pkt)
        vendor     = _oui_vendor(client_mac)
        ts         = datetime.now().strftime("%H:%M:%S")

        with self._lock:
            rec = ProbeRecord(
                client_mac=client_mac,
                ssid=ssid if ssid else "[wildcard]",
                vendor=vendor,
                ts=ts,
                rssi=rssi,
            )
            self._probes.append(rec)
            if len(self._probes) > PROBE_LOG_MAX:
                self._probes = self._probes[-PROBE_LOG_MAX:]
            self.stats["probes_seen"] += 1

            # Alert: wildcard probe from suspicious adapter
            # Probe alerts are rare one-off events — no debounce needed here
            if not ssid and _is_pentest_vendor(vendor):
                self._alert(
                    atype="ROGUE_PROBE",
                    actor=client_mac,
                    sev="MEDIUM",
                    size=len(pkt),
                    detail=(
                        f"Wildcard Probe from pentest adapter ({vendor}). "
                        f"MAC={client_mac}, RSSI={rssi} dBm — possible network scanner."
                    )
                )

    # ── Deauth handler ────────────────────────────────────────────────────────

    def _on_deauth(self, pkt):
        """
        Detect Deauthentication flood attacks.
        A single source sending many Deauth frames in 5 s → CRITICAL alert.

        Rate Limiting:
          self.stats["deauths_seen"] increments on EVERY packet (real-time counter).
          _alert() is called at most once per ALERT_DEBOUNCE_SECS per attacker MAC,
          preventing I/O bottleneck during mass deauth floods (e.g. aireplay-ng).
        """
        dot11  = pkt[Dot11]
        src    = dot11.addr2 or ""
        dst    = dot11.addr1 or ""
        reason = 0
        now    = time.time()

        # Extract reason code from Dot11Deauth layer
        try:
            if pkt.haslayer(Dot11Deauth):
                reason = int(pkt[Dot11Deauth].reason)
        except Exception:
            pass

        should_block = False
        with self._lock:
            # Always increment raw counter — UI stats stay accurate in real time
            self.stats["deauths_seen"] += 1

            dq = self._deauth_track[src]
            dq.append(now)
            # Keep only last 5 seconds
            while dq and now - dq[0] > 5.0:
                dq.popleft()

            count = len(dq)
            if count >= DEAUTH_FLOOD_THRESH:
                # Debounce: fire heavy _alert() at most once per window per attacker.
                # The flood continues being counted in dq and deauths_seen above.
                if not self._is_debounced("DEAUTH_FLOOD", src, now):
                    self._alert(
                        atype="DEAUTH_FLOOD",
                        actor=src,
                        sev="CRITICAL",
                        size=len(pkt),
                        detail=(
                            f"Deauth Flood: {count} frames/5s from {src} → {dst}. "
                            f"Reason code {reason}. "
                            f"Network clients may be forcibly disconnected!"
                        )
                    )
                    should_block = True

        # block_ip acquires engine.lock — must be called OUTSIDE self._lock
        # to avoid lock-order deadlock between wifi_monitor and threat_engine.
        if should_block and self.engine is not None:
            try:
                self.engine.block_ip(src)
            except Exception:
                pass

    def _on_disassoc(self, pkt):
        """
        Treat mass Disassociation similarly to Deauth.

        Rate Limiting:
          self.stats["deauths_seen"] increments on every packet.
          _alert() fires at most once per ALERT_DEBOUNCE_SECS per source MAC.
        """
        dot11 = pkt[Dot11]
        src   = dot11.addr2 or ""
        now   = time.time()
        with self._lock:
            # Always count for real-time statistics
            self.stats["deauths_seen"] += 1

            dq = self._deauth_track[src]
            dq.append(now)
            while dq and now - dq[0] > 5.0:
                dq.popleft()
            if len(dq) >= DEAUTH_FLOOD_THRESH:
                # Debounce: skip heavy I/O if this attacker fired recently
                if not self._is_debounced("DISASSOC_FLOOD", src, now):
                    self._alert(
                        atype="DISASSOC_FLOOD",
                        actor=src,
                        sev="HIGH",
                        size=len(pkt),
                        detail=f"Disassoc Flood: {len(dq)} frames/5s from {src}"
                    )

    # ── Authentication handler ────────────────────────────────────────────────

    def _on_auth(self, pkt):
        """
        Detect authentication storms (brute-force / PMKID attacks).

        Rate Limiting:
          The EAPOL timestamp list grows on every packet (accurate burst counting).
          _alert() fires at most once per ALERT_DEBOUNCE_SECS per source MAC,
          preventing GUI freeze when a tool like hcxdumptool hammers auth frames.
        """
        dot11 = pkt[Dot11]
        src   = dot11.addr2 or ""
        now   = time.time()
        with self._lock:
            # Always append timestamp — burst counter stays accurate
            self._eapol_track[src].append(now)
            self._eapol_track[src] = [
                t for t in self._eapol_track[src] if now - t < 10
            ]
            if len(self._eapol_track[src]) >= 20:
                # Debounce: fire heavy _alert() at most once per window per attacker
                if not self._is_debounced("AUTH_STORM", src, now):
                    self._alert(
                        atype="AUTH_STORM",
                        actor=src,
                        sev="HIGH",
                        size=len(pkt),
                        detail=(
                            f"Auth Storm: {len(self._eapol_track[src])} auth frames/10s "
                            f"from {src} — possible PMKID or WPA handshake harvesting."
                        )
                    )

    # ── Data frame handler (EAPOL / WPA handshake) ────────────────────────────

    def _on_data(self, pkt):
        """Detect EAPOL handshake capture attempts (WPA cracking tool).

        Rate Limiting:
          EAPOL frames burst during any WPA4-way handshake (normal reconnect
          or forced deauth attack). Without debouncing, every frame triggers
          _alert() — locking engine.lock + disk I/O + DB write hundreds of
          times per second, which serialises the capture thread with the GUI
          event loop and causes the application to freeze.
          Debounce window matches ALERT_DEBOUNCE_SECS (default 4.5 s).
        """
        if not SCAPY_AVAILABLE:
            return
        try:
            # EAPOL uses EtherType 0x888e
            raw = bytes(pkt)
            if b'\x88\x8e' in raw:
                dot11 = pkt[Dot11]
                src   = dot11.addr2 or ""
                now   = time.time()
                # Debounce: heavy _alert() path fires at most once per window
                # per source MAC. Raw EAPOL frames still pass through the
                # handler so future counters can be added without this risk.
                with self._lock:
                    if self._is_debounced("EAPOL_CAPTURE", src, now):
                        return
                self._alert(
                    atype="EAPOL_CAPTURE",
                    actor=src,
                    sev="HIGH",
                    size=len(pkt),
                    detail=(
                        f"EAPOL / WPA Handshake frame captured from {src}. "
                        f"If repeated, attacker may be harvesting credentials."
                    )
                )
        except Exception:
            pass

    # ── Device fingerprinting ─────────────────────────────────────────────────

    def fingerprint_check(self, mac: str, claimed_device_type: str) -> Optional[str]:
        """
        Check if the OUI vendor is consistent with the claimed device type.
        Returns a warning string if suspicious, else None.

        Example: MAC=F0:D1:A9:xx:xx:xx (Intel) but claimed_device_type="iPhone"
        → Intel makes laptop Wi-Fi chips, not iPhones → suspicious.
        """
        vendor = _oui_vendor(mac)
        if vendor == "Unknown":
            return None  # cannot say anything

        allowed_types = VENDOR_DEVICE_TYPES.get(vendor, set())
        if claimed_device_type.lower() not in allowed_types and allowed_types:
            return (
                f"Fingerprint mismatch: MAC {mac} belongs to {vendor} "
                f"(typical devices: {', '.join(allowed_types)}), "
                f"but device claims to be '{claimed_device_type}'. "
                f"Possible MAC spoofing!"
            )
        return None

    def check_ap_fingerprint(self, bssid: str, claimed_vendor: str) -> bool:
        """
        Returns True if OUI-derived vendor matches claimed_vendor.
        Used to cross-check AP vendor field in Beacon vs OUI database.
        """
        real_vendor = _oui_vendor(bssid)
        return real_vendor.lower() in claimed_vendor.lower() or claimed_vendor == "Unknown"

    # ── Alert injection ───────────────────────────────────────────────────────

    def _alert(self, atype: str, actor: str, sev: str, size: int, detail: str = "", target: str = "BROADCAST"):
        ts = datetime.now().strftime("%H:%M:%S")
        logging.warning("[WiFiMonitor] %s | %s | %s | %s", sev, atype, actor, detail)

        if self.engine is not None:
            try:
                with self.engine.lock:
                    self.engine._raise_alert(atype, actor, sev, size)
                    self.engine.threat_count += 1
                    self.engine.proto_counts["802.11"] += 1
            except Exception:
                logging.exception("[WiFiMonitor] Failed to inject alert into engine")

            try:
                result = {
                    "pkt":         None,
                    "status":      f"⚠ {atype}",
                    "color":       "#FF3B5C" if sev in ("CRITICAL", "HIGH") else "#FFCC00",
                    "threats":     [(atype, actor, sev)],
                    "app":         f"📡 {atype}",
                    "src":         actor,
                    "dst":         target,
                    "size":        size,
                    "time":        ts,
                    "proto":       "802.11",
                    "vendor":      _oui_vendor(actor),
                    "detail":      detail,
                    "wifi_threat": True,
                    "wifi_actor":  actor,
                    "wifi_target": target,
                    "wifi_sev":    sev,
                    "wifi_type":   atype,
                    "wifi_msg":    detail,
                }
                # Drain one old item if queue is near capacity so Wi-Fi alerts
                # are never silently dropped — they are always more important
                # than already-queued generic traffic records.
                q = self.engine.result_q
                if q.full():
                    try:
                        q.get_nowait()
                    except Exception:
                        pass
                q.put_nowait(result)
            except Exception:
                pass

        # Persist to database if available
        try:
            from core.database import get_db
            db = get_db()
            if db:
                db.insert_alert({
                    "time": ts, "type": atype,
                    "actor": actor, "severity": sev, "size": size
                })
        except Exception:
            pass


# ── Standalone demo (run without the full SOC Sentinel GUI) ──────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC Sentinel WiFiMonitor CLI")
    parser.add_argument("iface", help="Monitor-mode interface (e.g. wlan0mon)")
    parser.add_argument("--trusted", help="MAC to mark as trusted", default=None)
    args = parser.parse_args()

    print(f"[*] SOC Sentinel WiFiMonitor — listening on {args.iface}")
    print("[*] Press Ctrl+C to stop\n")

    mon = WiFiMonitor()
    if args.trusted:
        mon.trust_device(args.trusted, alias="CLI-trusted")
    mon.start(args.iface)

    try:
        while True:
            time.sleep(5)
            stats = mon.get_stats()
            aps   = mon.get_aps()
            print(f"\n[Stats] APs={stats['aps_seen']}  "
                  f"Probes={stats['probes_seen']}  "
                  f"Deauths={stats['deauths_seen']}  "
                  f"EvilTwins={stats['evil_twins']}  "
                  f"Mgmt-PPS={stats['mgmt_pps']}")
            for ap in aps[-5:]:
                rogue = "⚠ ROGUE" if ap["is_rogue"] else ""
                print(f"  {rogue}  SSID={ap['ssid']!r:20s}  "
                      f"BSSID={ap['bssid']}  "
                      f"Ch={ap['channel']}  "
                      f"RSSI={ap['rssi']} dBm  "
                      f"Vendor={ap['vendor']}")
    except KeyboardInterrupt:
        mon.stop()
        print("\n[*] Stopped.")
