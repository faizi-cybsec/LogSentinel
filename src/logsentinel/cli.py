"""Command-line interface for LogSentinel."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import AnalysisSummary, Severity
from .parsers import SUPPORTED_FORMATS, parse_file
from .reporters import (
    render_terminal_report,
    write_csv_report,
    write_html_report,
    write_json_report,
)
from .rules import RuleEngine, RuleValidationError, load_rules
from .threat_intel import ThreatIntelFeed
from .triage import group_alerts_into_incidents


def _default_data_dir(subdir: str) -> Path:
    """Resolve bundled rules/ or feeds/ directory relative to package or CWD."""
    pkg_root = Path(__file__).resolve().parents[2]
    candidate = pkg_root / subdir
    if candidate.exists():
        return candidate
    return Path.cwd() / subdir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="LogSentinel: SOC Log Analyzer, Detection Rule Engine & MITRE ATT&CK Triage CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a security log file and triage incidents")
    analyze.add_argument("log_file", type=Path, help="Path to log file (auth.log, web access, or JSONL)")
    analyze.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default="auto",
        help="Log format (default: auto)",
    )
    analyze.add_argument(
        "--rules-dir",
        type=Path,
        default=_default_data_dir("rules"),
        help="Directory containing JSON detection rules",
    )
    analyze.add_argument(
        "--ioc-feed",
        type=Path,
        default=_default_data_dir("feeds") / "default_iocs.json",
        help="Path to JSON IOC threat-intel feed",
    )
    analyze.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="LOW",
        help="Minimum alert severity to include (default: LOW)",
    )
    analyze.add_argument("--json-out", type=Path, help="Write SIEM-ready JSON report to path")
    analyze.add_argument("--csv-out", type=Path, help="Write analyst CSV report to path")
    analyze.add_argument("--html-out", type=Path, help="Write HTML incident report to path")
    analyze.add_argument("--no-color", action="store_true", help="Disable ANSI terminal colors")
    analyze.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with code 2 if HIGH or CRITICAL incidents are found (useful in CI/CD)",
    )

    list_cmd = sub.add_parser("list-rules", help="List loaded detection rules and MITRE ATT&CK mappings")
    list_cmd.add_argument(
        "--rules-dir",
        type=Path,
        default=_default_data_dir("rules"),
        help="Directory containing JSON detection rules",
    )

    val_cmd = sub.add_parser("validate-rules", help="Validate all detection rule files in a directory")
    val_cmd.add_argument(
        "--rules-dir",
        type=Path,
        default=_default_data_dir("rules"),
        help="Directory containing JSON detection rules",
    )

    return parser


def run_analyze(args: argparse.Namespace) -> int:
    if not args.log_file.exists():
        print(f"[ERROR] Log file not found: {args.log_file}", file=sys.stderr)
        return 1

    start = time.perf_counter()
    detected_fmt, events, total_lines, skipped = parse_file(args.log_file, fmt=args.format)

    rules = load_rules(args.rules_dir)
    engine = RuleEngine(rules)
    alerts = engine.evaluate(events)

    if args.ioc_feed and args.ioc_feed.exists():
        feed = ThreatIntelFeed.from_json(args.ioc_feed)
        alerts = feed.enrich_alerts(alerts)

    min_rank = Severity(args.min_severity).rank
    alerts = [a for a in alerts if a.severity.rank >= min_rank]
    incidents = group_alerts_into_incidents(alerts)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    summary = AnalysisSummary(
        source_file=str(args.log_file),
        detected_format=detected_fmt,
        total_lines=total_lines,
        parsed_events=len(events),
        skipped_lines=skipped,
        rules_loaded=len(rules),
        alerts=alerts,
        incidents=incidents,
        generated_at=datetime.now(timezone.utc),
        duration_ms=elapsed_ms,
    )

    use_color = (not args.no_color) and sys.stdout.isatty()
    print(render_terminal_report(summary, use_color=use_color))

    if args.json_out:
        write_json_report(summary, args.json_out)
        print(f"[+] JSON report written to {args.json_out}")
    if args.csv_out:
        write_csv_report(summary, args.csv_out)
        print(f"[+] CSV report written to {args.csv_out}")
    if args.html_out:
        write_html_report(summary, args.html_out)
        print(f"[+] HTML report written to {args.html_out}")

    if args.fail_on_high and any(
        inc.severity in (Severity.HIGH, Severity.CRITICAL) for inc in incidents
    ):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "analyze":
            return run_analyze(args)
        if args.command == "list-rules":
            rules = load_rules(args.rules_dir)
            for r in rules:
                print(
                    f"{r.id:<14} [{r.severity.value:<8}] {r.mitre_technique:<10} "
                    f"({r.rule_type:<9}) {r.title}"
                )
            return 0
        if args.command == "validate-rules":
            rules = load_rules(args.rules_dir)
            print(f"[OK] Validated {len(rules)} detection rules in {args.rules_dir}")
            return 0
    except (RuleValidationError, FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    return 0
