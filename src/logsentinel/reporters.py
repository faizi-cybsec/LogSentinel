"""Terminal, JSON, CSV, and self-contained HTML reporters for SOC triage output."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .models import AnalysisSummary, Severity

_ANSI = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "MAGENTA": "\033[95m",
}


def _c(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_ANSI.get(color, '')}{text}{_ANSI['RESET']}"


def _sev_color(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "MAGENTA",
        Severity.HIGH: "RED",
        Severity.MEDIUM: "YELLOW",
        Severity.LOW: "CYAN",
    }[sev]


def render_terminal_report(summary: AnalysisSummary, use_color: bool = True) -> str:
    """Format a human-readable SOC triage summary for terminal output."""
    lines: list[str] = []
    lines.append(_c("=" * 72, "CYAN", use_color))
    lines.append(_c("  LOGSENTINEL - SOC THREAT TRIAGE & DETECTION REPORT", "BOLD", use_color))
    lines.append(_c("=" * 72, "CYAN", use_color))
    lines.append(f"  Source File     : {summary.source_file}")
    lines.append(f"  Detected Format : {summary.detected_format}")
    lines.append(
        f"  Events Parsed   : {summary.parsed_events}/{summary.total_lines} lines "
        f"(skipped: {summary.skipped_lines})"
    )
    lines.append(f"  Rules Loaded    : {summary.rules_loaded}")
    lines.append(f"  Alerts / Incid. : {len(summary.alerts)} alerts -> {len(summary.incidents)} incidents")
    lines.append(f"  Analysis Time   : {summary.duration_ms:.1f} ms")
    lines.append("")

    sev_counts = Counter(a.severity.value for a in summary.alerts)
    lines.append(
        "  Severity Breakdown: "
        + f"CRITICAL={sev_counts.get('CRITICAL', 0)}  "
        + f"HIGH={sev_counts.get('HIGH', 0)}  "
        + f"MEDIUM={sev_counts.get('MEDIUM', 0)}  "
        + f"LOW={sev_counts.get('LOW', 0)}"
    )
    lines.append("")

    if not summary.incidents:
        lines.append(_c("  [OK] No security incidents detected.", "GREEN", use_color))
        lines.append(_c("=" * 72, "CYAN", use_color))
        return "\n".join(lines)

    lines.append(_c("  PRIORITIZED INCIDENTS", "BOLD", use_color))
    lines.append("  " + "-" * 68)
    for inc in summary.incidents:
        sev_tag = _c(f"[{inc.severity.value}]", _sev_color(inc.severity), use_color)
        lines.append(
            f"  {inc.incident_id} {sev_tag} Risk={inc.risk_score}/100 | {inc.title}"
        )
        lines.append(
            f"    Window   : {inc.first_seen.isoformat()} -> {inc.last_seen.isoformat()} ({inc.alert_count} alerts)"
        )
        lines.append(f"    MITRE    : {', '.join(inc.mitre_techniques)}")
        if inc.usernames:
            lines.append(f"    Users    : {', '.join(inc.usernames)}")
        if inc.ioc_matches:
            lines.append(_c(f"    IOC Hits : {', '.join(inc.ioc_matches)}", "RED", use_color))
        if inc.recommended_actions:
            lines.append(f"    Response : {inc.recommended_actions[0]}")
        lines.append("")

    lines.append(_c("=" * 72, "CYAN", use_color))
    return "\n".join(lines)


def summary_to_dict(summary: AnalysisSummary) -> dict[str, Any]:
    """Serialize AnalysisSummary into a JSON-compatible dictionary."""
    return {
        "metadata": {
            "source_file": summary.source_file,
            "detected_format": summary.detected_format,
            "total_lines": summary.total_lines,
            "parsed_events": summary.parsed_events,
            "skipped_lines": summary.skipped_lines,
            "rules_loaded": summary.rules_loaded,
            "generated_at": summary.generated_at.isoformat(),
            "duration_ms": round(summary.duration_ms, 2),
        },
        "counts": {
            "alerts": len(summary.alerts),
            "incidents": len(summary.incidents),
            "by_severity": dict(Counter(a.severity.value for a in summary.alerts)),
        },
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity.value,
                "risk_score": inc.risk_score,
                "source_ip": inc.source_ip,
                "usernames": inc.usernames,
                "mitre_techniques": inc.mitre_techniques,
                "first_seen": inc.first_seen.isoformat(),
                "last_seen": inc.last_seen.isoformat(),
                "alert_count": inc.alert_count,
                "ioc_matches": inc.ioc_matches,
                "recommended_actions": inc.recommended_actions,
            }
            for inc in summary.incidents
        ],
        "alerts": [
            {
                "alert_id": a.alert_id,
                "rule_id": a.rule_id,
                "rule_title": a.rule_title,
                "severity": a.severity.value,
                "risk_score": a.risk_score,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique": a.mitre_technique,
                "timestamp": a.timestamp.isoformat(),
                "source_ip": a.source_ip,
                "username": a.username,
                "evidence_count": a.evidence_count,
                "ioc_matches": a.ioc_matches,
                "description": a.description,
                "remediation": a.remediation,
                "sample_raw": a.sample_raw,
            }
            for a in summary.alerts
        ],
    }


def write_json_report(summary: AnalysisSummary, output_path: Path) -> None:
    """Write SIEM/SOAR-ready JSON report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(summary_to_dict(summary), indent=2),
        encoding="utf-8",
    )


def write_csv_report(summary: AnalysisSummary, output_path: Path) -> None:
    """Write flat CSV alert report for analyst triage."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "alert_id",
        "severity",
        "risk_score",
        "timestamp",
        "rule_id",
        "rule_title",
        "mitre_tactic",
        "mitre_technique",
        "source_ip",
        "username",
        "evidence_count",
        "ioc_matches",
        "description",
        "remediation",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for a in summary.alerts:
            writer.writerow(
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity.value,
                    "risk_score": a.risk_score,
                    "timestamp": a.timestamp.isoformat(),
                    "rule_id": a.rule_id,
                    "rule_title": a.rule_title,
                    "mitre_tactic": a.mitre_tactic,
                    "mitre_technique": a.mitre_technique,
                    "source_ip": a.source_ip or "",
                    "username": a.username or "",
                    "evidence_count": a.evidence_count,
                    "ioc_matches": "; ".join(a.ioc_matches),
                    "description": a.description,
                    "remediation": a.remediation,
                }
            )


def write_html_report(summary: AnalysisSummary, output_path: Path) -> None:
    """Write a self-contained, XSS-safe dark-mode HTML SOC Incident Report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sev_counts = Counter(a.severity.value for a in summary.alerts)

    incident_rows = []
    for inc in summary.incidents:
        sev_cls = inc.severity.value.lower()
        iocs_html = (
            "<br>".join(html.escape(x) for x in inc.ioc_matches)
            if inc.ioc_matches
            else "<span class='muted'>None</span>"
        )
        mitre_html = " ".join(
            f"<span class='tag'>{html.escape(t)}</span>" for t in inc.mitre_techniques
        )
        actions_html = (
            html.escape(inc.recommended_actions[0])
            if inc.recommended_actions
            else "-"
        )
        incident_rows.append(
            f"""
            <tr>
              <td><code>{html.escape(inc.incident_id)}</code></td>
              <td><span class="badge {sev_cls}">{html.escape(inc.severity.value)}</span></td>
              <td><strong>{inc.risk_score}</strong>/100</td>
              <td>{html.escape(inc.title)}</td>
              <td><code>{html.escape(inc.source_ip or 'local')}</code></td>
              <td>{mitre_html}</td>
              <td>{inc.alert_count}</td>
              <td>{iocs_html}</td>
              <td>{actions_html}</td>
            </tr>
            """
        )

    if not incident_rows:
        incident_rows.append(
            '<tr><td colspan="9" class="muted">No incidents detected.</td></tr>'
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LogSentinel SOC Incident Report</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); margin:0; padding:24px; }}
  .container {{ max-width: 1280px; margin: 0 auto; }}
  h1 {{ margin: 0 0 6px; font-size: 24px; }}
  .muted {{ color: var(--muted); font-size: 13px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 20px 0; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }}
  .card .num {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: top; }}
  th {{ background: #1c2128; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
  .badge {{ padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
  .critical {{ background: #4c1d95; color: #ede9fe; }}
  .high {{ background: #7f1d1d; color: #fee2e2; }}
  .medium {{ background: #78350f; color: #fef3c7; }}
  .low {{ background: #0c4a6e; color: #e0f2fe; }}
  .tag {{ display:inline-block; background:#21262d; border:1px solid var(--border); border-radius:4px; padding:1px 6px; font-size:11px; margin:1px; }}
</style>
</head>
<body>
<div class="container">
  <h1>LogSentinel SOC Incident Report</h1>
  <div class="muted">
    Source: <code>{html.escape(summary.source_file)}</code> |
    Format: <code>{html.escape(summary.detected_format)}</code> |
    Generated: {html.escape(summary.generated_at.isoformat())}
  </div>
  <div class="grid">
    <div class="card"><div class="muted">Events Parsed</div><div class="num">{summary.parsed_events}</div></div>
    <div class="card"><div class="muted">Incidents</div><div class="num">{len(summary.incidents)}</div></div>
    <div class="card"><div class="muted">Total Alerts</div><div class="num">{len(summary.alerts)}</div></div>
    <div class="card"><div class="muted">Critical / High</div><div class="num">{sev_counts.get('CRITICAL', 0) + sev_counts.get('HIGH', 0)}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Severity</th><th>Risk</th><th>Incident</th><th>Source IP</th>
        <th>MITRE ATT&amp;CK</th><th>Alerts</th><th>IOC Matches</th><th>Recommended Action</th>
      </tr>
    </thead>
    <tbody>
      {''.join(incident_rows)}
    </tbody>
  </table>
</div>
</body>
</html>
"""
    output_path.write_text(doc, encoding="utf-8")
