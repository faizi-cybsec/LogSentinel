"""Sigma-inspired detection rule loader, validator, and correlation engine."""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Any

from .models import Alert, DetectionRule, SecurityEvent, Severity

REQUIRED_RULE_FIELDS = {
    "id",
    "title",
    "description",
    "severity",
    "mitre_tactic",
    "mitre_technique",
    "rule_type",
    "formats",
}
VALID_RULE_TYPES = {"match", "threshold", "sequence"}


class RuleValidationError(ValueError):
    """Raised when a detection rule file fails schema validation."""


def _parse_rule_dict(raw: dict[str, Any], source: str) -> DetectionRule:
    missing = REQUIRED_RULE_FIELDS - set(raw.keys())
    if missing:
        raise RuleValidationError(f"Rule in {source} missing required fields: {sorted(missing)}")

    rule_type = raw["rule_type"]
    if rule_type not in VALID_RULE_TYPES:
        raise RuleValidationError(f"Rule {raw['id']} has invalid rule_type '{rule_type}'")

    try:
        severity = Severity(str(raw["severity"]).upper())
    except ValueError as exc:
        raise RuleValidationError(f"Rule {raw['id']} has invalid severity '{raw['severity']}'") from exc

    return DetectionRule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        description=str(raw["description"]),
        severity=severity,
        mitre_tactic=str(raw["mitre_tactic"]),
        mitre_technique=str(raw["mitre_technique"]),
        rule_type=rule_type,
        formats=[str(f) for f in raw["formats"]],
        match=dict(raw.get("match", {})),
        group_by=str(raw.get("group_by", "source_ip")),
        threshold=int(raw.get("threshold", 1)),
        window_seconds=int(raw.get("window_seconds", 60)),
        first_match=dict(raw.get("first_match", {})),
        then_match=dict(raw.get("then_match", {})),
        min_first_count=int(raw.get("min_first_count", 3)),
        tags=[str(t) for t in raw.get("tags", [])],
        remediation=str(raw.get("remediation", "")),
    )


def load_rules(rules_dir: Path) -> list[DetectionRule]:
    """Load and validate all JSON detection rules from a directory."""
    if not rules_dir.exists():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()

    for path in sorted(rules_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                raise RuleValidationError(f"Expected object in {path.name}")
            rule = _parse_rule_dict(item, path.name)
            if rule.id in seen_ids:
                raise RuleValidationError(f"Duplicate rule id '{rule.id}' in {path.name}")
            seen_ids.add(rule.id)
            rules.append(rule)

    return rules


def _compile_condition(cond: dict[str, Any]) -> dict[str, Any]:
    """Pre-compile regex patterns inside a rule condition dictionary."""
    compiled = dict(cond)
    if "regex_any" in cond:
        compiled["_compiled_regexes"] = [
            re.compile(pattern, re.IGNORECASE) for pattern in cond["regex_any"]
        ]
    return compiled


def _event_matches(event: SecurityEvent, cond: dict[str, Any]) -> bool:
    """Evaluate whether a SecurityEvent satisfies a compiled condition block."""
    for key, expected in cond.items():
        if key == "_compiled_regexes":
            continue
        if key == "contains_any":
            haystack = event.raw.lower()
            if not any(str(needle).lower() in haystack for needle in expected):
                return False
            continue
        if key == "regex_any":
            regexes = cond.get("_compiled_regexes", [])
            target_text = f"{event.target or ''} {event.raw}"
            if not any(rx.search(target_text) for rx in regexes):
                return False
            continue
        if key == "status_in":
            if event.status_code not in expected:
                return False
            continue
        if key == "status_gte":
            if event.status_code is None or event.status_code < int(expected):
                return False
            continue

        actual = event.get_field(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False

    return True


def _make_alert(
    seq_num: int,
    rule: DetectionRule,
    trigger_event: SecurityEvent,
    evidence: list[SecurityEvent],
    description_override: str | None = None,
) -> Alert:
    usernames = [e.username for e in evidence if e.username]
    primary_user = usernames[-1] if usernames else trigger_event.username
    samples = [e.raw for e in evidence[-5:]]

    # Slight score boost for high-volume evidence
    volume_bonus = min(8, max(0, len(evidence) - 1))
    risk_score = min(100, rule.severity.base_score + volume_bonus)

    return Alert(
        alert_id=f"ALT-{seq_num:04d}",
        rule_id=rule.id,
        rule_title=rule.title,
        severity=rule.severity,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
        timestamp=trigger_event.timestamp,
        source_ip=trigger_event.source_ip,
        username=primary_user,
        description=description_override or rule.description,
        evidence_count=len(evidence),
        sample_raw=samples,
        remediation=rule.remediation,
        risk_score=risk_score,
    )


class RuleEngine:
    """Evaluates stateless and stateful detection rules over sorted SecurityEvents."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    def evaluate(self, events: list[SecurityEvent]) -> list[Alert]:
        """Run all applicable rules over the event stream and return generated alerts."""
        alerts: list[Alert] = []
        seq = 1

        for rule in self.rules:
            relevant = [e for e in events if e.source_format in rule.formats or "all" in rule.formats]
            if not relevant:
                continue

            if rule.rule_type == "match":
                cond = _compile_condition(rule.match)
                for ev in relevant:
                    if _event_matches(ev, cond):
                        alerts.append(_make_alert(seq, rule, ev, [ev]))
                        seq += 1

            elif rule.rule_type == "threshold":
                cond = _compile_condition(rule.match)
                window = timedelta(seconds=rule.window_seconds)
                buckets: dict[str, deque[SecurityEvent]] = defaultdict(deque)

                for ev in relevant:
                    if not _event_matches(ev, cond):
                        continue
                    key = str(ev.get_field(rule.group_by) or "unknown")
                    q = buckets[key]
                    q.append(ev)
                    cutoff = ev.timestamp - window
                    while q and q[0].timestamp < cutoff:
                        q.popleft()

                    if len(q) >= rule.threshold:
                        evidence = list(q)
                        desc = (
                            f"{rule.description} "
                            f"({len(evidence)} matching events in {rule.window_seconds}s for {rule.group_by}={key})"
                        )
                        alerts.append(_make_alert(seq, rule, ev, evidence, description_override=desc))
                        seq += 1
                        q.clear()

            elif rule.rule_type == "sequence":
                first_cond = _compile_condition(rule.first_match)
                then_cond = _compile_condition(rule.then_match)
                window = timedelta(seconds=rule.window_seconds)
                first_buckets: dict[str, deque[SecurityEvent]] = defaultdict(deque)

                for ev in relevant:
                    key = str(ev.get_field(rule.group_by) or "unknown")
                    q = first_buckets[key]
                    cutoff = ev.timestamp - window
                    while q and q[0].timestamp < cutoff:
                        q.popleft()

                    if _event_matches(ev, first_cond):
                        q.append(ev)
                    elif _event_matches(ev, then_cond) and len(q) >= rule.min_first_count:
                        evidence = list(q) + [ev]
                        desc = (
                            f"{rule.description} "
                            f"({len(q)} prior failed attempts followed by success within {rule.window_seconds}s)"
                        )
                        alerts.append(_make_alert(seq, rule, ev, evidence, description_override=desc))
                        seq += 1
                        q.clear()

        alerts.sort(key=lambda a: (a.risk_score, a.timestamp), reverse=True)
        return alerts
