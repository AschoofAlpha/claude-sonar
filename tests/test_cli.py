"""CLI tests for python -m claude_shield (1.3.2)."""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield import __version__
from claude_shield.__main__ import build_parser, main
from claude_shield.models import AuditCheck, AuditReport, PlatformInfo, PrivacyMetadata
from claude_shield.report import format_report, group_checks


def _fake_audit_result(**overrides):
    checks = [
        AuditCheck(
            id="network.mode",
            title="Rule mode",
            category="network",
            status="pass",
            severity="info",
            confidence="confirmed",
            explanation="Observed Mode='Rule'.",
            recommendation="Confirm the setting in the active proxy client before changing it.",
        ),
        AuditCheck(
            id="network.allow_lan",
            title="LAN access disabled",
            category="network",
            status="warning",
            severity="medium",
            confidence="probable",
            explanation="Observed AllowLan=True.",
            recommendation="Disable LAN access unless explicitly required.",
        ),
    ]
    report = AuditReport(
        schema_version="1.0",
        tool_version=__version__,
        generated_at="2026-08-10T00:00:00Z",
        platform=PlatformInfo(os="Windows", version="11", hostname="host"),
        privacy=PrivacyMetadata(redaction_enabled=True, salt_used=False),
        checks=checks,
        summary={"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 1},
        errors=[],
    )
    result = {
        "checks": checks,
        "summary": report.summary,
        "snapshot": {"System": {}},
        "report": report,
        "report_dict": {
            "schema_version": "1.0",
            "tool_version": __version__,
            "summary": report.summary,
            "checks": [{"id": c.id, "status": c.status} for c in checks],
        },
        "report_markdown": format_report(checks),
    }
    result.update(overrides)
    return result


class TestReportHelpers(unittest.TestCase):
    def test_format_report_and_groups(self):
        checks = _fake_audit_result()["checks"]
        md = format_report(checks)
        self.assertIn("Must fix", md)
        self.assertIn("Optional consistency", md)
        self.assertIn("Leave alone", md)
        self.assertIn("| 检查项 |", md)
        groups = group_checks(checks)
        self.assertIn("must_fix", groups)
        self.assertTrue(any(c.id == "network.allow_lan" for c in groups["must_fix"]))


class TestCliParser(unittest.TestCase):
    def test_defaults_offline(self):
        args = build_parser().parse_args([])
        self.assertFalse(args.online)
        self.assertFalse(args.as_json)
        self.assertEqual(args.timeout, 5.0)
        self.assertIsNone(args.intended_region)

    def test_flags(self):
        args = build_parser().parse_args(
            ["--online", "--json", "--timeout", "8", "--intended-region", "JP"]
        )
        self.assertTrue(args.online)
        self.assertTrue(args.as_json)
        self.assertEqual(args.timeout, 8.0)
        self.assertEqual(args.intended_region, "JP")


class TestCliMain(unittest.TestCase):
    def test_markdown_default_offline(self):
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake) as mocked:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main([])
            self.assertEqual(code, 0)
            out = buf.getvalue()
            self.assertIn("Claude Shield Audit Report", out)
            self.assertIn("network.mode", out)
            self.assertIn("Must fix", out)
            kwargs = mocked.call_args.kwargs
            self.assertFalse(kwargs.get("online"))
            self.assertTrue(kwargs.get("include_recommendations"))

    def test_json_output(self):
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buf.getvalue())
            self.assertIn("report_dict", payload)
            self.assertIn("summary", payload)
            self.assertEqual(payload["summary"]["medium"], 1)

    def test_online_flag_forwarded(self):
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake) as mocked:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--online", "--timeout", "3", "--intended-region", "US"])
            self.assertEqual(code, 0)
            kwargs = mocked.call_args.kwargs
            self.assertTrue(kwargs.get("online"))
            self.assertEqual(kwargs.get("probe_timeout"), 3.0)
            self.assertEqual(kwargs.get("intended_region"), "US")

    def test_never_online_by_default(self):
        """Regression: invoking with no args must not enable online probes."""
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake) as mocked:
            with redirect_stdout(io.StringIO()):
                main([])
            self.assertFalse(mocked.call_args.kwargs.get("online", True))

    def test_collector_error_exit_code(self):
        from claude_shield.analyze import CollectorError

        with mock.patch(
            "claude_shield.analyze.run_full_audit",
            side_effect=CollectorError("boom"),
        ):
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = main([])
            self.assertEqual(code, 2)
            self.assertIn("collector error", err.getvalue())

    def test_module_version(self):
        self.assertEqual(__version__, "1.3.2")


if __name__ == "__main__":
    unittest.main()
