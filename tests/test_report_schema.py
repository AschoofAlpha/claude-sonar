import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from claude_shield.analyze import analyze_snapshot, build_audit_report, run_full_audit
from claude_shield.models import to_dict
from claude_shield.schema import validate_report
from claude_shield.redaction import Redactor
from claude_shield import __version__


class TestReportSchema(unittest.TestCase):
    def test_build_report_validates(self):
        checks = analyze_snapshot({
            "ClaudeCode": {"DisableTelemetryActive": True, "DisableErrorReportingActive": True, "DisableNonessentialTrafficActive": True},
            "System": {"Culture": "en-US", "UICulture": "en-US", "SystemLocale": "en-US"},
        }, include_recommendations=False, redactor=Redactor())
        report = build_audit_report(checks, snapshot={"System": {"OS": "Windows", "OSVersion": "11", "ComputerName": "DESKTOP"}}, redactor=Redactor())
        report_dict = to_dict(report)
        self.assertTrue(validate_report(report_dict))
        self.assertEqual(report_dict["schema_version"], "1.0")
        self.assertEqual(report_dict["tool_version"], __version__)
        self.assertIn("checks", report_dict)
        self.assertNotIn("findings", report_dict)

    def test_run_full_audit_includes_report(self):
        result = run_full_audit(online=False, probe_timeout=3)
        self.assertIn("report", result)
        self.assertIn("report_dict", result)
        self.assertTrue(validate_report(result["report_dict"]))
        locale = next((c for c in result["checks"] if c.id == "system.locale"), None)
        if locale is not None:
            self.assertNotIn("<PATH:", locale.explanation)


if __name__ == "__main__":
    unittest.main()
