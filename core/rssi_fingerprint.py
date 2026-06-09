"""Evil Twin detection via RSSI/channel spatial fingerprinting."""

from __future__ import annotations

import statistics
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Set


@dataclass
class SpatialThreat:
    threat_type: str
    severity: str
    bssid: str
    ssid: str
    detail: str
    rssi: int = -100
    channel: int = 0


class RSSIFingerprintEngine:
    def __init__(self, std_threshold: float = 8.0):
        self._profiles: Dict[str, dict] = {}
        self._ssid_map: Dict[str, Set[str]] = {}
        self._bssid_channels: Dict[str, Set[int]] = {}
        self._lock = threading.Lock()
        self.std_threshold = std_threshold

    def record(self, bssid: str, ssid: str, channel: int, rssi: int) -> List[SpatialThreat]:
        if not bssid or rssi <= -99:
            return []
        bssid = bssid.upper()
        threats: List[SpatialThreat] = []
        with self._lock:
            if bssid not in self._profiles:
                self._profiles[bssid] = {"ssid": ssid, "channel": channel,
                    "samples": deque(maxlen=50)}
            p = self._profiles[bssid]
            p["samples"].append(rssi)
            if channel:
                p["channel"] = channel
            ch_set = self._bssid_channels.setdefault(bssid, set())
            if channel and ch_set and channel not in ch_set:
                threats.append(SpatialThreat("BSSID_CHANNEL_SPOOF", "CRITICAL", bssid, ssid,
                    f"Same BSSID on channels {sorted(ch_set)} and {channel}", rssi, channel))
            if channel:
                ch_set.add(channel)
            if ssid:
                self._ssid_map.setdefault(ssid, set()).add(bssid)
                for peer in self._ssid_map[ssid] - {bssid}:
                    pp = self._profiles.get(peer)
                    if pp and len(pp["samples"]) >= 3:
                        mean = statistics.mean(pp["samples"])
                        if abs(rssi - mean) >= 15:
                            threats.append(SpatialThreat("EVIL_TWIN_RSSI", "CRITICAL", bssid, ssid,
                                f"SSID '{ssid}': {bssid} ({rssi}dBm) vs {peer} ({mean:.0f}dBm)", rssi, channel))
            if len(p["samples"]) >= 8:
                sd = statistics.stdev(p["samples"]) if len(p["samples"]) >= 2 else 0
                if sd >= self.std_threshold:
                    threats.append(SpatialThreat("RSSI_UNSTABLE", "HIGH", bssid, ssid,
                        f"Unstable RSSI σ={sd:.1f}", rssi, channel))
        return threats

    def get_heatmap_data(self) -> List[dict]:
        with self._lock:
            out = []
            for bssid, p in self._profiles.items():
                samples = p["samples"]
                mean = int(statistics.mean(samples)) if samples else -100
                out.append({"bssid": bssid, "ssid": p.get("ssid", ""), "channel": p.get("channel", 1),
                    "rssi": mean, "intensity": max(0, min(100, 100 + mean))})
            return out
