"""Wi-Fi risk score 1–10."""

from typing import Dict, List


def compute_risk_score(stats: dict, alerts: List[dict], heatmap: List[dict]) -> dict:
    score = 10.0
    deductions = []
    evil = stats.get("evil_twins", 0) + stats.get("spatial_threats", 0)
    if evil:
        d = min(4, evil * 1.5)
        score -= d
        deductions.append(f"Evil Twin: -{d:.1f}")
    if stats.get("deauths_seen", 0) > 20:
        d = min(3, stats["deauths_seen"] / 30)
        score -= d
    crit = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    if crit:
        score -= min(2, crit * 0.5)
    final = max(1, min(10, round(score, 1)))
    label = "Excellent" if final >= 9 else "Good" if final >= 7 else "Fair" if final >= 5 else "Poor"
    return {"score": final, "label": label, "grade": f"{final}/10", "deductions": deductions}
