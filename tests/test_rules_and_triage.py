"""Unit tests for rule evaluation, correlation, IOC enrichment, and incident triage."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logsentinel.models import Severity
from logsentinel.parsers import parse_file
from logsentinel.rules import RuleEngine, load_rules
from logsentinel.threat_intel import ThreatIntelFeed
from logsentinel.triage import group_alerts_into_incidents

ROOT = Path(__file__).resolve().parents[1]


class TestRulesAndTriage(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = load_rules(ROOT / "rules")
        self.feed = ThreatIntelFeed.from_json(ROOT / "feeds" / "default_iocs.json")
        self.engine = RuleEngine(self.rules)

    def test_auth_sample_detects_bruteforce_compromise_and_privesc(self) -> None:
        _, events, _, _ = parse_file(ROOT / "samples" / "auth.log", fmt="auth", default_year=2026)
        alerts = self.engine.evaluate(events)
        alerts = self.feed.enrich_alerts(alerts)

        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("LS-AUTH-001", rule_ids)  # Brute force threshold
        self.assertIn("LS-AUTH-002", rule_ids)  # Brute force -> success sequence
        self.assertIn("LS-PRIV-001", rule_ids)  # sudo /bin/bash
        self.assertIn("LS-PRIV-002", rule_ids)  # useradd

        # 185.220.101.45 is in default_iocs.json (both malicious_ips and tor_exit_nodes)
        ssh_alerts = [a for a in alerts if a.source_ip == "185.220.101.45"]
        self.assertTrue(ssh_alerts)
        self.assertTrue(any("Tor Exit Node" in ioc for a in ssh_alerts for ioc in a.ioc_matches))

        incidents = group_alerts_into_incidents(alerts)
        self.assertGreaterEqual(len(incidents), 2)
        self.assertEqual(incidents[0].severity, Severity.CRITICAL)

    def test_web_sample_detects_sqli_lfi_and_scanner(self) -> None:
        _, events, _, _ = parse_file(ROOT / "samples" / "web_access.log", fmt="web")
        alerts = self.feed.enrich_alerts(self.engine.evaluate(events))
        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("LS-WEB-001", rule_ids)
        self.assertIn("LS-WEB-002", rule_ids)
        self.assertIn("LS-WEB-003", rule_ids)

    def test_cloud_jsonl_detects_root_no_mfa_and_key_creation(self) -> None:
        _, events, _, _ = parse_file(ROOT / "samples" / "cloud_events.jsonl", fmt="jsonl")
        alerts = self.feed.enrich_alerts(self.engine.evaluate(events))
        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("LS-CLOUD-001", rule_ids)
        self.assertIn("LS-CLOUD-002", rule_ids)


if __name__ == "__main__":
    unittest.main()
