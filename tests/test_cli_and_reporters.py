"""End-to-end integration tests for CLI and JSON/CSV/HTML report exports."""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logsentinel.cli import main

ROOT = Path(__file__).resolve().parents[1]


class TestCliAndReporters(unittest.TestCase):
    def test_cli_analyze_exports_all_reports_and_fail_on_high(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            json_out = tmp_dir / "report.json"
            csv_out = tmp_dir / "report.csv"
            html_out = tmp_dir / "report.html"

            rc = main(
                [
                    "analyze",
                    str(ROOT / "samples" / "auth.log"),
                    "--rules-dir",
                    str(ROOT / "rules"),
                    "--ioc-feed",
                    str(ROOT / "feeds" / "default_iocs.json"),
                    "--json-out",
                    str(json_out),
                    "--csv-out",
                    str(csv_out),
                    "--html-out",
                    str(html_out),
                    "--no-color",
                    "--fail-on-high",
                ]
            )
            self.assertEqual(rc, 2)  # HIGH/CRITICAL incidents found
            self.assertTrue(json_out.exists())
            self.assertTrue(csv_out.exists())
            self.assertTrue(html_out.exists())

            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["metadata"]["detected_format"], "auth")
            self.assertGreater(payload["counts"]["alerts"], 0)
            self.assertGreater(payload["counts"]["incidents"], 0)

            with csv_out.open("r", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertGreater(len(rows), 0)

            html_text = html_out.read_text(encoding="utf-8")
            self.assertIn("LogSentinel SOC Incident Report", html_text)
            self.assertIn("185.220.101.45", html_text)

    def test_cli_validate_and_list_rules(self) -> None:
        self.assertEqual(main(["validate-rules", "--rules-dir", str(ROOT / "rules")]), 0)
        self.assertEqual(main(["list-rules", "--rules-dir", str(ROOT / "rules")]), 0)

    def test_cli_missing_file_returns_1(self) -> None:
        self.assertEqual(main(["analyze", "does_not_exist.log"]), 1)


if __name__ == "__main__":
    unittest.main()
