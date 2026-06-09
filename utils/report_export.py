"""JSON and PDF incident export."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional


def export_json(path: str, alerts: list, packets: Optional[list] = None, meta: Optional[dict] = None) -> int:
    report = {"generated": datetime.now().isoformat(), "generator": "SOC Sentinel v2",
              "meta": meta or {}, "incidents": alerts, "packets_sample": (packets or [])[:500],
              "incident_count": len(alerts)}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return len(alerts)


def export_csv(path: str, rows: list, headers: list) -> int:
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)
    return len(rows)


def export_pdf(path: str, alerts: list, meta: Optional[dict] = None) -> bool:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        return False
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph("SOC Sentinel — Incident Report", styles["Title"]), Spacer(1, 12)]
    data = [["Time", "Type", "Actor", "Severity"]]
    for a in alerts[:200]:
        data.append([str(a.get("time", "")), str(a.get("type", "")),
                     str(a.get("actor", "")), str(a.get("severity", ""))])
    t = Table(data)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey)]))
    story.append(t)
    doc.build(story)
    return True
