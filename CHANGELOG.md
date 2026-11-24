# Changelog

All notable changes to **LogSentinel** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-24

### Added
- Multi-format log parsers with auto-detection for Linux `auth.log`, Apache/Nginx Combined Web Access logs, and JSONL cloud/IAM audit logs.
- Sigma-inspired JSON detection engine supporting `match`, `threshold` (sliding window), and `sequence` (multi-stage correlation) rules.
- 9 built-in detection rules mapped to MITRE ATT&CK tactics and techniques (`T1110.001`, `T1078`, `T1548.003`, `T1136.001`, `T1190`, `T1595.002`, `T1098.001`, `T1078.004`).
- Offline Threat Intelligence (IOC) enrichment for malicious IPs, CIDRs, Tor exit nodes, and offensive User-Agents.
- Alert deduplication, incident grouping, and 0–100 risk scoring.
- Terminal, SIEM-ready JSON, analyst CSV, and XSS-safe dark-mode HTML reporters.
- GitHub Actions CI pipeline and `unittest` test suite.
