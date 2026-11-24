"""Alert triage and incident grouping for SOC analyst workflows."""

from __future__ import annotations

from collections import defaultdict

from .models import Alert, Incident, Severity


def group_alerts_into_incidents(alerts: list[Alert]) -> list[Incident]:
    """Group related alerts by source IP (or rule ID when no IP) into prioritized Incidents."""
    if not alerts:
        return []

    grouped: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        key = alert.source_ip if alert.source_ip else f"host:{alert.rule_id}"
        grouped[key].append(alert)

    incidents: list[Incident] = []
    for idx, (group_key, group_alerts) in enumerate(grouped.items(), start=1):
        group_alerts.sort(key=lambda a: a.timestamp)
        max_score = max(a.risk_score for a in group_alerts)
        # Multi-stage attacks from the same source raise overall incident risk
        multi_stage_bonus = min(15, 5 * (len({a.rule_id for a in group_alerts}) - 1))
        incident_score = min(100, max_score + multi_stage_bonus)
        severity = Severity.from_score(incident_score)

        techniques = list(dict.fromkeys(a.mitre_technique for a in group_alerts))
        usernames = list(dict.fromkeys(a.username for a in group_alerts if a.username))
        iocs = list(dict.fromkeys(ioc for a in group_alerts for ioc in a.ioc_matches))
        actions = list(dict.fromkeys(a.remediation for a in group_alerts if a.remediation))

        source_ip = None if group_key.startswith("host:") else group_key
        top_rule = max(group_alerts, key=lambda a: a.risk_score).rule_title
        title = (
            f"{top_rule} from {source_ip}"
            if source_ip
            else f"{top_rule} (Local Host Activity)"
        )

        incidents.append(
            Incident(
                incident_id=f"INC-{idx:04d}",
                title=title,
                severity=severity,
                risk_score=incident_score,
                first_seen=group_alerts[0].timestamp,
                last_seen=group_alerts[-1].timestamp,
                source_ip=source_ip,
                usernames=usernames,
                mitre_techniques=techniques,
                alerts=group_alerts,
                ioc_matches=iocs,
                recommended_actions=actions,
            )
        )

    incidents.sort(key=lambda inc: (inc.risk_score, inc.alert_count), reverse=True)
    return incidents
