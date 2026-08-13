"""CLI tests for python -m claude_shield (1.4.0)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield import __version__
from claude_shield.__main__ import build_parser, main
from claude_shield.diff import diff_reports, format_diff_markdown
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
            "checks": [
                {"id": c.id, "status": c.status, "severity": c.severity, "title": c.title}
                for c in checks
            ],
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

    def test_format_report_compact(self):
            checks = _fake_audit_result()["checks"]
            md = format_report(checks, compact=True, lang="en")
            self.assertIn("Must fix", md)
            self.assertNotIn("## All results", md)
            self.assertNotIn("## 全部结果", md)
            self.assertNotIn("## Leave alone", md)
            self.assertNotIn("## 保持不动", md)
            md_zh = format_report(checks, compact=True, lang="zh")
            self.assertIn("必须处理", md_zh)
            self.assertNotIn("## 全部结果", md_zh)
            self.assertNotIn("## 保持不动", md_zh)


class TestCliParser(unittest.TestCase):
    def test_defaults_offline(self):
        args = build_parser().parse_args([])
        self.assertFalse(args.online)
        self.assertFalse(args.as_json)
        self.assertEqual(args.timeout, 5.0)
        self.assertIsNone(args.intended_region)
        self.assertIsNone(args.intended_mode)
        self.assertIsNone(args.out)
        self.assertIsNone(args.diff)
        self.assertFalse(args.compact)
        self.assertFalse(args.full)
        self.assertEqual(args.lang, "zh")

    def test_flags(self):
        args = build_parser().parse_args(
            [
                "--online",
                "--json",
                "--timeout",
                "8",
                "--intended-region",
                "JP",
                "--intended-mode",
                "full_tunnel",
                "--compact",
                "--out",
                "out.md",
                "--diff",
                "prev.json",
                "--lang",
                "en",
            ]
        )
        self.assertTrue(args.online)
        self.assertTrue(args.as_json)
        self.assertEqual(args.timeout, 8.0)
        self.assertEqual(args.intended_region, "JP")
        self.assertEqual(args.intended_mode, "full_tunnel")
        self.assertTrue(args.compact)
        self.assertEqual(args.out, "out.md")
        self.assertEqual(args.diff, "prev.json")
        self.assertEqual(args.lang, "en")


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
            self.assertEqual(kwargs.get("lang"), "zh")
            self.assertIsNone(kwargs.get("intended_mode"))

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

    def test_intended_mode_and_lang_forwarded(self):
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake) as mocked:
            with redirect_stdout(io.StringIO()):
                code = main(["--intended-mode", "system_proxy", "--lang", "en"])
            self.assertEqual(code, 0)
            kwargs = mocked.call_args.kwargs
            self.assertEqual(kwargs.get("intended_mode"), "system_proxy")
            self.assertEqual(kwargs.get("lang"), "en")

    def test_compact_skips_full_sections(self):
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--compact", "--lang", "en"])
            self.assertEqual(code, 0)
            out = buf.getvalue()
            self.assertIn("Must fix", out)
            self.assertNotIn("## All results", out)
            self.assertNotIn("## Leave alone", out)

    def test_full_overrides_compact(self):
        fake = _fake_audit_result()
        with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--compact", "--full", "--lang", "en"])
            self.assertEqual(code, 0)
            out = buf.getvalue()
            self.assertIn("## All results", out)
            self.assertIn("## Leave alone", out)

    def test_out_writes_file_and_stdout(self):
        fake = _fake_audit_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.md")
            with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = main(["--out", path, "--lang", "en"])
                self.assertEqual(code, 0)
                self.assertIn("Claude Shield Audit Report", buf.getvalue())
                written = Path(path).read_text(encoding="utf-8")
                self.assertIn("Claude Shield Audit Report", written)
                self.assertIn("Must fix", written)

    def test_out_json(self):
        fake = _fake_audit_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = main(["--json", "--out", path])
                self.assertEqual(code, 0)
                payload = json.loads(Path(path).read_text(encoding="utf-8"))
                self.assertIn("report_dict", payload)
                self.assertEqual(json.loads(buf.getvalue())["summary"]["medium"], 1)

    def test_diff_markdown_appends_section(self):
        fake = _fake_audit_result()
        previous = {
            "report_dict": {
                "checks": [
                    {"id": "network.mode", "status": "fail", "severity": "high"},
                    {"id": "network.old", "status": "pass", "severity": "info"},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            prev_path = os.path.join(tmp, "prev.json")
            Path(prev_path).write_text(json.dumps(previous), encoding="utf-8")
            with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = main(["--diff", prev_path, "--lang", "en"])
                self.assertEqual(code, 0)
                out = buf.getvalue()
                self.assertIn("Audit diff", out)
                self.assertIn("network.mode", out)
                self.assertIn("network.old", out)
                self.assertIn("network.allow_lan", out)

    def test_diff_json_includes_key(self):
        fake = _fake_audit_result()
        previous = {
            "checks": [
                {"id": "network.mode", "status": "pass", "severity": "info"},
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            prev_path = os.path.join(tmp, "prev.json")
            Path(prev_path).write_text(json.dumps(previous), encoding="utf-8")
            with mock.patch("claude_shield.analyze.run_full_audit", return_value=fake):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = main(["--json", "--diff", prev_path])
                self.assertEqual(code, 0)
                payload = json.loads(buf.getvalue())
                self.assertIn("diff", payload)
                self.assertGreaterEqual(payload["diff"]["summary"]["added"], 1)

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
        self.assertEqual(__version__, "1.4.9")


class TestDiffHelpers(unittest.TestCase):
    def test_diff_reports_status_change(self):
        prev = {"checks": [{"id": "a", "status": "pass", "severity": "info"}]}
        curr = {"checks": [{"id": "a", "status": "fail", "severity": "high"}]}
        d = diff_reports(prev, curr)
        self.assertEqual(d["summary"]["changed"], 1)
        self.assertEqual(d["status_changed"][0]["before"], "pass")
        self.assertEqual(d["status_changed"][0]["after"], "fail")
        md = format_diff_markdown(d, lang="en")
        self.assertIn("Audit diff", md)


if __name__ == "__main__":
    unittest.main()
