<div align="center">

# 🛡️ LogSentinel

**SOC Log Analyzer, Sigma-Style Detection Rule Engine & MITRE ATT&CK Threat Triage CLI**

[![CI](https://github.com/faizi-cybsec/LogSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/faizi-cybsec/LogSentinel/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib)-brightgreen.svg)](pyproject.toml)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](https://attack.mitre.org/)

</div>

---

## Overview

**LogSentinel** is a lightweight, zero-dependency Python security operations (SOC) tool built for **L1/L2 SOC analysts**, **incident responders**, and **security engineers**. It ingests raw heterogeneous logs, normalizes them into a unified event schema, runs stateless and stateful correlation rules mapped to **MITRE ATT&CK**, enriches matches against offline **IOC threat intelligence**, and groups noisy alerts into prioritized **Incidents**.

### Key Capabilities

- **Multi-Format Log Ingestion & Auto-Detection** — Parses Linux `auth.log` (`sshd`, `sudo`, `useradd`), Apache/Nginx Combined Web Access logs, and JSONL Cloud/IAM audit logs into a normalized `SecurityEvent` stream.
- **3-Mode Detection Engine** — Supports single-event `match` rules, sliding time-window `threshold` bursts, and multi-stage `sequence` correlation (e.g., brute-force followed by successful login).
- **Offline IOC Threat Intelligence** — Enriches alerts against known malicious IPs, CIDRs, Tor exit nodes, and offensive User-Agents (`sqlmap`, `gobuster`, `nikto`, etc.) with automatic risk-score escalation.
- **Incident Triage & Risk Scoring (0–100)** — Deduplicates and groups related alerts by attacker IP or host activity so analysts focus on high-priority incidents instead of raw log noise.
- **SIEM/SOAR & Executive Reporting** — Generates terminal summaries, SIEM-ready **JSON**, analyst **CSV**, and XSS-safe dark-mode **HTML** incident reports.
- **Zero External Dependencies** — Built purely on the Python 3.10+ standard library; runs anywhere without dependency conflicts.

---

## Architecture

```text
  [ auth.log | web_access.log | cloud_events.jsonl ]
                          │
                          ▼
             Log Parsers & Auto-Detector
                          │
                          ▼
          Normalized SecurityEvent Stream
                          │
                          ▼
       Rule Engine (match / threshold / sequence)
                          │
                          ▼
        Offline Threat Intel (IOC Enrichment)
                          │
                          ▼
       Incident Triage & Risk Scoring (0–100)
                          │
                          ▼
        Terminal  │  JSON  │  CSV  │  HTML Report
```

---

## Quick Start

### Option 1: Install as a CLI Tool (Recommended)

```bash
git clone https://github.com/faizi-cybsec/LogSentinel.git
cd LogSentinel
pip install -e .

logsentinel list-rules
logsentinel analyze samples/auth.log --html-out reports/auth_report.html
```

### Option 2: Run Directly Without Installation

```bash
PYTHONPATH=src python -m logsentinel analyze samples/auth.log
PYTHONPATH=src python -m logsentinel analyze samples/web_access.log --json-out reports/web.json
PYTHONPATH=src python -m logsentinel analyze samples/cloud_events.jsonl --csv-out reports/cloud.csv
```

### Example Terminal Output

```text
========================================================================
  LOGSENTINEL - SOC THREAT TRIAGE & DETECTION REPORT
========================================================================
  Source File     : samples/auth.log
  Detected Format : auth
  Events Parsed   : 10/10 lines (skipped: 0)
  Rules Loaded    : 9
  Alerts / Incid. : 4 alerts -> 3 incidents
  Analysis Time   : 30.8 ms

  Severity Breakdown: CRITICAL=2  HIGH=1  MEDIUM=1  LOW=0

  PRIORITIZED INCIDENTS
  --------------------------------------------------------------------
  INC-0001 [CRITICAL] Risk=100/100 | SSH Brute-Force Attack Detected from 185.220.101.45
    Window   : 2026-11-24T23:04:12+00:00 -> 2026-11-24T23:04:29+00:00 (2 alerts)
    MITRE    : T1110.001, T1078
    Users    : ubuntu
    IOC Hits : Known Malicious IP (Known SSH Brute-Force Botnet), Tor Exit Node
    Response : Block source IP at perimeter firewall/fail2ban, enforce key-based SSH auth, and disable root login.
```

---

## Built-in Detection Rules (MITRE ATT&CK)

| Rule ID | Title | Severity | Type | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| `LS-AUTH-001` | SSH Brute-Force Attack Detected | `HIGH` | `threshold` | `T1110.001` (Credential Access) |
| `LS-AUTH-002` | Potential SSH Account Compromise After Brute-Force | `CRITICAL` | `sequence` | `T1078` (Initial Access) |
| `LS-PRIV-001` | Suspicious Sudo Privilege Escalation Command | `HIGH` | `match` | `T1548.003` (Privilege Escalation) |
| `LS-PRIV-002` | Local User Account Created | `MEDIUM` | `match` | `T1136.001` (Persistence) |
| `LS-WEB-001` | SQL Injection Probe Detected in HTTP Request | `HIGH` | `match` | `T1190` (Initial Access) |
| `LS-WEB-002` | Path Traversal / Local File Inclusion Attempt | `HIGH` | `match` | `T1190` (Initial Access) |
| `LS-WEB-003` | Automated Web Vulnerability Scanner / Recon Burst | `MEDIUM` | `threshold` | `T1595.002` (Reconnaissance) |
| `LS-CLOUD-001` | Cloud IAM Access Key Created | `MEDIUM` | `match` | `T1098.001` (Persistence) |
| `LS-CLOUD-002` | Cloud Root Account Login Without MFA | `CRITICAL` | `match` | `T1078.004` (Initial Access) |

---

## CLI Reference

| Command / Flag | Description |
| :--- | :--- |
| `logsentinel analyze <file>` | Parse, detect, enrich, and triage a log file |
| `--format {auto,auth,web,jsonl}` | Override automatic log format detection |
| `--rules-dir <dir>` | Path to custom JSON detection rules directory |
| `--ioc-feed <file>` | Path to custom JSON threat-intel IOC feed |
| `--min-severity {LOW,MEDIUM,HIGH,CRITICAL}` | Filter alerts below a minimum severity |
| `--json-out <file>` | Export SIEM/SOAR-ready JSON report |
| `--csv-out <file>` | Export flat CSV alert table |
| `--html-out <file>` | Export self-contained dark-mode HTML incident report |
| `--fail-on-high` | Exit with code `2` if `HIGH` or `CRITICAL` incidents are found |
| `logsentinel list-rules` | Print all loaded rules and MITRE ATT&CK mappings |
| `logsentinel validate-rules` | Validate rule schemas before deploying to production |

---

## Authoring Custom Rules

Drop any `.json` file into `rules/` (single rule object or array of rules). Example `sequence` rule:

```json
{
  "id": "LS-AUTH-002",
  "title": "Potential SSH Account Compromise After Brute-Force",
  "description": "Repeated failed SSH logins followed by a successful login from the same source IP.",
  "severity": "CRITICAL",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "T1078",
  "rule_type": "sequence",
  "formats": ["auth"],
  "group_by": "source_ip",
  "window_seconds": 300,
  "min_first_count": 3,
  "first_match": { "action": ["ssh_login", "ssh_invalid_user"], "outcome": "failure" },
  "then_match": { "action": "ssh_login", "outcome": "success" },
  "remediation": "Immediately isolate host, terminate active SSH sessions, and rotate credentials."
}
```

---

## Project Structure

```text
LogSentinel/
├── .github/
│   ├── ISSUE_TEMPLATE/        # Bug report & new detection rule templates
│   ├── workflows/ci.yml       # GitHub Actions CI (Python 3.10–3.13)
│   └── pull_request_template.md
├── feeds/
│   └── default_iocs.json      # Offline threat-intel feed (IPs, CIDRs, Tor, UAs)
├── rules/                     # JSON detection rules mapped to MITRE ATT&CK
├── samples/                   # Realistic auth, web, and cloud sample logs
├── src/logsentinel/
│   ├── cli.py                 # Argument parsing & pipeline orchestration
│   ├── models.py              # SecurityEvent, DetectionRule, Alert, Incident
│   ├── parsers.py             # Auto-detecting parsers (auth, web, jsonl)
│   ├── reporters.py           # Terminal, JSON, CSV, and HTML reporters
│   ├── rules.py               # Rule loader, validator & correlation engine
│   ├── threat_intel.py        # Offline IOC enrichment & score boosting
│   ├── triage.py              # Alert deduplication & incident grouping
│   └── py.typed               # PEP 561 type marker
├── tests/                     # Unit & end-to-end integration tests
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── SECURITY.md
└── pyproject.toml
```

---

## Testing

```bash
python -m unittest discover -s tests -v
```

---

## Contributing & Security

- Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
- To report a security issue, please follow [SECURITY.md](SECURITY.md).
- Released under the [MIT License](LICENSE) by **Faizan Ahmad** ([`@faizi-cybsec`](https://github.com/faizi-cybsec)).
