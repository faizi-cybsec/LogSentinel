"""Unit tests for log format detection and parsers."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logsentinel.parsers import (
    detect_format,
    parse_auth_log_line,
    parse_file,
    parse_jsonl_line,
    parse_web_access_line,
)


class TestParsers(unittest.TestCase):
    def test_parse_auth_ssh_failed_and_accepted(self) -> None:
        fail_line = "Nov 24 23:04:01 web01 sshd[101]: Failed password for invalid user admin from 185.220.101.45 port 44101 ssh2"
        ev_fail = parse_auth_log_line(fail_line, 1, default_year=2026)
        self.assertIsNotNone(ev_fail)
        self.assertEqual(ev_fail.action, "ssh_login")
        self.assertEqual(ev_fail.outcome, "failure")
        self.assertEqual(ev_fail.source_ip, "185.220.101.45")
        self.assertEqual(ev_fail.username, "admin")
        self.assertTrue(ev_fail.metadata["invalid_user"])

        ok_line = "2026-11-24T23:04:29Z web01 sshd[102]: Accepted publickey for faizan from 10.0.1.30 port 52910 ssh2"
        ev_ok = parse_auth_log_line(ok_line, 2)
        self.assertIsNotNone(ev_ok)
        self.assertEqual(ev_ok.outcome, "success")
        self.assertEqual(ev_ok.username, "faizan")
        self.assertEqual(ev_ok.source_ip, "10.0.1.30")

    def test_parse_auth_sudo_and_useradd(self) -> None:
        sudo_line = "Nov 24 23:05:02 web01 sudo[4155]:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"
        ev_sudo = parse_auth_log_line(sudo_line, 1, default_year=2026)
        self.assertIsNotNone(ev_sudo)
        self.assertEqual(ev_sudo.action, "sudo_exec")
        self.assertEqual(ev_sudo.username, "ubuntu")
        self.assertEqual(ev_sudo.target, "/bin/bash")

        ua_line = "Nov 24 23:05:40 web01 useradd[4180]: new user: name=svc_backup, UID=1009, GID=1009"
        ev_ua = parse_auth_log_line(ua_line, 2, default_year=2026)
        self.assertIsNotNone(ev_ua)
        self.assertEqual(ev_ua.action, "user_created")
        self.assertEqual(ev_ua.username, "svc_backup")

    def test_parse_web_access_line(self) -> None:
        line = '45.155.205.99 - - [24/Nov/2026:23:11:12 +0000] "GET /search?q=1+OR+1=1 HTTP/1.1" 200 8421 "-" "sqlmap/1.8"'
        ev = parse_web_access_line(line, 5)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.source_format, "web")
        self.assertEqual(ev.source_ip, "45.155.205.99")
        self.assertEqual(ev.status_code, 200)
        self.assertEqual(ev.user_agent, "sqlmap/1.8")

    def test_parse_jsonl_line(self) -> None:
        line = '{"timestamp": "2026-11-24T23:16:10Z", "source_ip": "198.51.100.77", "username": "root", "action": "ConsoleLogin", "outcome": "success", "mfa_used": false}'
        ev = parse_jsonl_line(line, 1)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.source_format, "jsonl")
        self.assertEqual(ev.action, "ConsoleLogin")
        self.assertFalse(ev.metadata["mfa_used"])

    def test_detect_format_and_parse_file(self) -> None:
        self.assertEqual(detect_format(['{"action": "Login"}']), "jsonl")
        self.assertEqual(
            detect_format(['10.0.0.1 - - [24/Nov/2026:23:10:01 +0000] "GET / HTTP/1.1" 200 100 "-" "curl"']),
            "web",
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.log"
            p.write_text(
                "Nov 24 23:01:10 host sshd[1]: Accepted publickey for deploy from 10.0.1.25 port 51200 ssh2\n"
                "malformed garbage line\n",
                encoding="utf-8",
            )
            fmt, events, total, skipped = parse_file(p, fmt="auto")
            self.assertEqual(fmt, "auth")
            self.assertEqual(len(events), 1)
            self.assertEqual(total, 2)
            self.assertEqual(skipped, 1)


if __name__ == "__main__":
    unittest.main()
