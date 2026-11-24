"""Log parsers and format auto-detection for heterogeneous security logs."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import SecurityEvent

SUPPORTED_FORMATS = ("auto", "auth", "web", "jsonl")

# Syslog prefix: "Nov 24 23:10:05 host sshd[1234]: ..." or "2026-11-24T23:10:05Z host ..."
_SYSLOG_LINE_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[\d+\])?:\s*(?P<msg>.+)$"
)

_SSH_FAILED_RE = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
_SSH_INVALID_USER_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
_SUDO_CMD_RE = re.compile(
    r"^(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$"
)
_USERADD_RE = re.compile(
    r"new user:\s*name=(?P<user>[^,\s]+)"
)

# Apache/Nginx Combined Log Format
_WEB_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _parse_syslog_timestamp(raw_ts: str, default_year: int) -> datetime:
    """Parse BSD syslog or ISO-8601 timestamp into timezone-aware UTC datetime."""
    raw_ts = raw_ts.strip()
    if raw_ts[0].isdigit():
        normalized = raw_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    collapsed = " ".join(raw_ts.split())
    dt = datetime.strptime(f"{default_year} {collapsed}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def _parse_web_timestamp(raw_ts: str) -> datetime:
    """Parse Apache/Nginx timestamp e.g. '24/Nov/2026:23:10:05 +0000'."""
    dt = datetime.strptime(raw_ts.strip(), "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)


def _parse_iso_timestamp(raw_ts: str | None) -> datetime:
    """Parse ISO-8601 timestamp with fallback to current UTC time."""
    if not raw_ts:
        return datetime.now(timezone.utc)
    normalized = str(raw_ts).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_auth_log_line(
    line: str, line_number: int, default_year: int | None = None
) -> SecurityEvent | None:
    """Parse a single Linux auth.log / syslog line into a SecurityEvent."""
    year = default_year or datetime.now(timezone.utc).year
    m = _SYSLOG_LINE_RE.match(line.strip())
    if not m:
        return None

    ts = _parse_syslog_timestamp(m.group("ts"), year)
    process = m.group("process").strip().lower()
    msg = m.group("msg").strip()
    host = m.group("host").strip()

    if m_fail := _SSH_FAILED_RE.search(msg):
        return SecurityEvent(
            timestamp=ts,
            source_format="auth",
            event_type="authentication",
            action="ssh_login",
            outcome="failure",
            source_ip=m_fail.group("ip"),
            username=m_fail.group("user"),
            target=host,
            raw=line.rstrip("\r\n"),
            line_number=line_number,
            metadata={
                "process": process,
                "auth_method": m_fail.group("method"),
                "invalid_user": bool(m_fail.group("invalid")),
            },
        )

    if m_acc := _SSH_ACCEPTED_RE.search(msg):
        return SecurityEvent(
            timestamp=ts,
            source_format="auth",
            event_type="authentication",
            action="ssh_login",
            outcome="success",
            source_ip=m_acc.group("ip"),
            username=m_acc.group("user"),
            target=host,
            raw=line.rstrip("\r\n"),
            line_number=line_number,
            metadata={"process": process, "auth_method": m_acc.group("method")},
        )

    if m_inv := _SSH_INVALID_USER_RE.search(msg):
        return SecurityEvent(
            timestamp=ts,
            source_format="auth",
            event_type="authentication",
            action="ssh_invalid_user",
            outcome="failure",
            source_ip=m_inv.group("ip"),
            username=m_inv.group("user"),
            target=host,
            raw=line.rstrip("\r\n"),
            line_number=line_number,
            metadata={"process": process, "invalid_user": True},
        )

    if process == "sudo" and (m_sudo := _SUDO_CMD_RE.search(msg)):
        return SecurityEvent(
            timestamp=ts,
            source_format="auth",
            event_type="privilege_escalation",
            action="sudo_exec",
            outcome="success",
            username=m_sudo.group("user"),
            target=m_sudo.group("cmd").strip(),
            raw=line.rstrip("\r\n"),
            line_number=line_number,
            metadata={"process": process, "command": m_sudo.group("cmd").strip()},
        )

    if "useradd" in process and (m_ua := _USERADD_RE.search(msg)):
        return SecurityEvent(
            timestamp=ts,
            source_format="auth",
            event_type="account_management",
            action="user_created",
            outcome="success",
            username=m_ua.group("user"),
            target=host,
            raw=line.rstrip("\r\n"),
            line_number=line_number,
            metadata={"process": process},
        )

    return SecurityEvent(
        timestamp=ts,
        source_format="auth",
        event_type="system",
        action=process,
        outcome="info",
        target=host,
        raw=line.rstrip("\r\n"),
        line_number=line_number,
        metadata={"process": process, "message": msg},
    )


def parse_web_access_line(line: str, line_number: int) -> SecurityEvent | None:
    """Parse a single Apache/Nginx Combined Log Format line."""
    m = _WEB_COMBINED_RE.match(line.strip())
    if not m:
        return None

    ts = _parse_web_timestamp(m.group("ts"))
    status = int(m.group("status"))
    user = m.group("user")
    outcome = "failure" if status >= 400 else "success"
    ua = m.group("ua") or ""

    return SecurityEvent(
        timestamp=ts,
        source_format="web",
        event_type="http_request",
        action=m.group("method"),
        outcome=outcome,
        source_ip=m.group("ip"),
        username=None if user == "-" else user,
        target=m.group("path"),
        user_agent=ua,
        status_code=status,
        raw=line.rstrip("\r\n"),
        line_number=line_number,
        metadata={
            "method": m.group("method"),
            "path": m.group("path"),
            "referer": m.group("referer") or "",
        },
    )


def parse_jsonl_line(line: str, line_number: int) -> SecurityEvent | None:
    """Parse a single JSONL security/cloud/firewall audit event."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    raw_ts = data.get("timestamp") or data.get("@timestamp") or data.get("ts") or data.get("eventTime")
    ts = _parse_iso_timestamp(raw_ts)

    source_ip = data.get("source_ip") or data.get("src_ip") or data.get("sourceIPAddress") or data.get("ip")
    username = data.get("username") or data.get("user") or data.get("actor")
    action = str(data.get("action") or data.get("event") or data.get("eventName") or "unknown")
    outcome = str(data.get("outcome") or data.get("result") or data.get("status") or "info").lower()
    target = data.get("target") or data.get("resource") or data.get("path")
    event_type = str(data.get("event_type") or data.get("category") or "cloud_audit")
    ua = data.get("user_agent") or data.get("userAgent")

    return SecurityEvent(
        timestamp=ts,
        source_format="jsonl",
        event_type=event_type,
        action=action,
        outcome=outcome,
        source_ip=str(source_ip) if source_ip else None,
        username=str(username) if username else None,
        target=str(target) if target else None,
        user_agent=str(ua) if ua else None,
        raw=line.rstrip("\r\n"),
        line_number=line_number,
        metadata=data,
    )


def detect_format(lines: Iterable[str]) -> str:
    """Heuristically detect log format from non-empty sample lines."""
    scores = {"jsonl": 0, "web": 0, "auth": 0}
    checked = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        checked += 1
        if stripped.startswith("{"):
            try:
                if isinstance(json.loads(stripped), dict):
                    scores["jsonl"] += 1
            except json.JSONDecodeError:
                pass
        elif _WEB_COMBINED_RE.match(stripped):
            scores["web"] += 1
        elif _SYSLOG_LINE_RE.match(stripped):
            scores["auth"] += 1
        if checked >= 20:
            break

    best_fmt = max(scores, key=lambda k: scores[k])
    return best_fmt if scores[best_fmt] > 0 else "auth"


def parse_file(
    path: Path, fmt: str = "auto", default_year: int | None = None
) -> tuple[str, list[SecurityEvent], int, int]:
    """Parse a log file into normalized SecurityEvent objects.

    Returns:
        (detected_format, events, total_lines, skipped_lines)
    """
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format '{fmt}'. Expected one of {SUPPORTED_FORMATS}.")

    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    detected = detect_format(raw_lines) if fmt == "auto" else fmt

    events: list[SecurityEvent] = []
    skipped = 0
    for idx, line in enumerate(raw_lines, start=1):
        if not line.strip():
            continue
        event: SecurityEvent | None = None
        if detected == "auth":
            event = parse_auth_log_line(line, idx, default_year=default_year)
        elif detected == "web":
            event = parse_web_access_line(line, idx)
        elif detected == "jsonl":
            event = parse_jsonl_line(line, idx)

        if event is None:
            skipped += 1
        else:
            events.append(event)

    events.sort(key=lambda e: e.timestamp)
    return detected, events, len(raw_lines), skipped
