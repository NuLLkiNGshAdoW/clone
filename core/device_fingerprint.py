"""Device fingerprinting: TTL, TCP window, DHCP, User-Agent."""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

try:
    import scapy.all as scapy
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


@dataclass
class DeviceProfile:
    ip: str
    os_guess: str = "Unknown"
    vendor: str = "Unknown"
    device_type: str = "unknown"
    risk_score: int = 0
    flags: List[str] = field(default_factory=list)
    packets: int = 0

    def to_dict(self) -> dict:
        return {"ip": self.ip, "os_guess": self.os_guess, "vendor": self.vendor,
                "device_type": self.device_type, "risk_score": self.risk_score,
                "flags": self.flags, "packets": self.packets}


class DeviceFingerprinter:
    def __init__(self, risk_threshold: int = 70):
        self._profiles: Dict[str, DeviceProfile] = {}
        self._port_track: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.risk_threshold = risk_threshold

    def analyze_packet(self, pkt, src_ip: str, vendor: str = "",
                       now: Optional[float] = None) -> List[Tuple[str, str, str]]:
        if not SCAPY_OK or not src_ip:
            return []
        now = now or time.time()
        prof = self._profiles.setdefault(src_ip, DeviceProfile(ip=src_ip))
        prof.packets += 1
        if vendor:
            prof.vendor = vendor
        threats = []
        if pkt.haslayer(scapy.IP):
            ttl = int(pkt[scapy.IP].ttl)
            if ttl <= 64:
                prof.os_guess = "Linux/Android"
            elif ttl <= 128:
                prof.os_guess = "Windows"
            else:
                prof.os_guess = "iOS/Network"
        if pkt.haslayer(scapy.TCP):
            win = int(pkt[scapy.TCP].window)
            if win == 65535:
                prof.os_guess = "Windows"
            dport = int(pkt[scapy.TCP].dport)
            self._port_track[src_ip].append((now, dport))
            recent = {p for t, p in self._port_track[src_ip] if now - t < 30}
            if len(recent) >= 12:
                prof.flags.append("PORT_SCAN")
                threats.append(("DEVICE_PORT_SCAN", src_ip, "HIGH"))
        if pkt.haslayer(scapy.DHCP):
            for opt in pkt[scapy.DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "hostname":
                    pass
        if pkt.haslayer(scapy.Raw):
            m = re.search(rb"User-Agent:\s*([^\r\n]+)", bytes(pkt[scapy.Raw].load), re.I)
            if m and "android" in m.group(1).decode("utf-8", errors="replace").lower():
                prof.os_guess = "Android"
        prof.risk_score = min(100, len(prof.flags) * 25 + (10 if prof.packets > 1000 else 0))
        if prof.risk_score >= self.risk_threshold:
            threats.append(("HIGH_RISK_DEVICE", src_ip, "HIGH"))
        return threats

    def get_all(self) -> List[dict]:
        return sorted([p.to_dict() for p in self._profiles.values()],
                      key=lambda x: x["risk_score"], reverse=True)
