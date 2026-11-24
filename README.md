# LogSentinel

**LogSentinel** is a zero-dependency Python SOC (Security Operations Center) log analyzer, Sigma-inspired detection rule engine, and MITRE ATT&CK threat triage CLI.

Built for SOC L1/L2 analysts, incident responders, and security engineers to ingest heterogeneous logs, correlate multi-stage attacks, enrich alerts with offline threat intelligence (IOCs), and generate prioritized incident reports.

---

## Why LogSentinel?

In real-world SOC environments, analysts deal with noisy, multi-format logs across Linux hosts, web servers, and cloud audit trails. LogSentinel bridges the gap between raw logs and actionable incident triage:

- **Multi-Format Log Ingestion & Normalization**: Auto-detects and normalizes Linux `auth.log` (SSH/sudo/useradd), Apache/Nginx Combined Web Access logs, and JSONL cloud/firewall audit logs into a unified `SecurityEvent` schema.
- **Stateful & Stateless Detection Engine**:
  - `match`: Single-event pattern/regex/field detection (SQLi, Path Traversal, Suspicious `sudo`, Root login without MFA).
  - `threshold`: Sliding time-window burst detection (e.g., `>= 5` failed SSH logins from one IP within `60s`).
  - `sequence`: Multi-stage attack correlation (e.g., SSH brute-force attempts followed by a successful login from the same IP).
- **Offline Threat Intelligence (IOC) Enrichment**: Matches source IPs, CIDRs, Tor exit nodes, and offensive tool User-Agents (`sqlmap`, `gobuster`, `nikto`, etc.) to boost risk scores and escalate severity.
- **Incident Grouping & Risk Scoring (0–100)**: Deduplicates noisy alerts into prioritized `Incident` objects grouped by attacker IP or host activity.
- **SIEM/SOAR & Executive Reporting**: Outputs clean terminal summaries, SIEM-ready **JSON**, analyst **CSV**, and XSS-safe dark-mode **HTML** incident reports.
- **Zero External Dependencies**: Pure Python 3.10+ standard library — runs anywhere without dependency conflicts.

---

## Architecture

```text
  [auth.log | web_access.log | cloud_events.jsonl]
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
     Incident Triage & Risk Scoring (0-100)
                        │
                        ▼
      Terminal  |  JSON  |  CSV  |  HTML Report
```

---

## Built-in Detection Rules (MITRE ATT&CK Mapped)

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

## Quick Start

### 1. Run directly (no installation required)

```bash
# Analyze Linux auth.log and export JSON + HTML reports
PYTHONPATH=src python -m logsentinel analyze samples/auth.log \
  --json-out reports/auth_report.json \
  --html-out reports/auth_report.html

# Analyze Nginx/Apache web access logs
PYTHONPATH=src python -m logsentinel analyze samples/web_access.log

# Analyze Cloud/IAM JSONL audit events
PYTHONPATH=src python -m logsentinel analyze samples/cloud_events.jsonl
```

### 2. Or install as a CLI tool

```bash
pip install -e .
logsentinel list-rules
logsentinel validate-rules
logsentinel analyze samples/auth.log --html-out reports/incident_report.html
```

### 3. CI/CD Gate Mode

Use `--fail-on-high` to exit with status code `2` when `HIGH` or `CRITICAL` incidents are detected:

```bash
logsentinel analyze samples/auth.log --fail-on-high
```

---

## Running Tests

```bash
python -m unittest discover -s tests -v
```

---

## Project Structure

```text
logsentinel/
├── .github/workflows/ci.yml   # GitHub Actions CI pipeline
├── feeds/default_iocs.json    # Sample threat intelligence IOC feed
├── rules/                     # JSON detection rules mapped to MITRE ATT&CK
├── samples/                   # Realistic auth, web, and cloud sample logs
├── src/logsentinel/           # Core package (parsers, rule engine, IOC, triage, reporters, CLI)
├── tests/                     # Unit & end-to-end integration tests
├── pyproject.toml             # PEP 621 package configuration
└── LICENSE                    # MIT License
```

---

## License

MIT License — see [LICENSE](LICENSE).
