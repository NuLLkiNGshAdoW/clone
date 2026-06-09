from datetime import datetime
import collections

class ThreatDetector:
    """
    Lightweight rule-based detector moved to core module.
    Produces human-readable alerts from live engine stats.
    """
    @staticmethod
    def detect(engine) -> list:
        alerts = []
        with engine.lock:
            syn   = engine.proto_counts.get("TCP", 0)
            icmp  = engine.proto_counts.get("ICMP", 0)
            dns   = engine.proto_counts.get("DNS", 0)
            total = engine.packet_stats.get("total", 0)
            bytes_ = engine.packet_stats.get("bytes", 0)
            blocked = len(engine.blocked_ips)
            n_alerts = len(engine.alerts)

            # Recent alerts (last 60s)
            now = datetime.now()
            recent = []
            for a in engine.alerts[-200:]:
                try:
                    at = datetime.strptime(a["time"], "%H:%M:%S").replace(
                        year=now.year, month=now.month, day=now.day)
                    if (now - at).total_seconds() < 60:
                        recent.append(a)
                except Exception:
                    pass

        crit  = sum(1 for a in recent if a.get("severity") == "CRITICAL")
        high  = sum(1 for a in recent if a.get("severity") == "HIGH")

        if crit > 0:
            alerts.append(f" {crit} CRITICAL threat(s) in last 60s")
        if high > 0:
            alerts.append(f" {high} HIGH severity alerts in last 60s")
        if icmp > engine.SIGS.get("ICMP_FLOOD", {}).get("thresh", 50) * 2:
            alerts.append(f"⚠ Very high ICMP traffic ({icmp} pkts) — possible scan/flood")
        if dns > 500:
            alerts.append(f"⚠ Elevated DNS queries ({dns}) — possible tunnelling")
        if blocked > 0:
            alerts.append(f" {blocked} IPs currently blocked")
        if bytes_ > 50 * 1024 * 1024:
            mb = bytes_ / (1024*1024)
            alerts.append(f" High data volume: {mb:.1f} MB captured")
        if not alerts:
            alerts.append(" No active threats detected at this moment")
        return alerts
