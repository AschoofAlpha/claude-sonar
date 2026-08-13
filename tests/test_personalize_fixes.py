"""Regression tests for personalize fixes: label de-duplication and CLI snapshot pass-through."""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_shield.personalize import detect_active_proxy


class TestDetectLabelDedup(unittest.TestCase):
    def test_duplicate_labels_collapsed(self):
        snap = {
            "System": {
                "PrimaryProxyProcesses": [
                    {"Name": "verge.exe", "Label": "Clash Verge", "Running": True},
                    {"Name": "verge-mihomo.exe", "Label": "Clash Verge", "Running": True},
                    {"Name": "clash-verge.exe", "Label": "Clash Verge", "Running": True},
                ],
                "MihomoProcessRunning": True,
                "ServiceModeActive": False,
                "MixedPortListening": True,
            },
            "Mihomo": {"ConfigPath": "C:\\fake\\config.yaml"},
        }
        profile = detect_active_proxy(snap)
        self.assertEqual(profile["primary"], "Clash Verge")
        self.assertEqual(profile["confidence"], "high")
        self.assertEqual(profile["labels"], ["Clash Verge"])

    def test_unknown_when_nothing_runs(self):
        profile = detect_active_proxy({"System": {}, "Mihomo": {}})
        self.assertIn("未识别", profile["primary"])
        self.assertEqual(profile["confidence"], "low")


class TestCliRenderPassesSnapshot(unittest.TestCase):
    def test_render_markdown_forwards_snapshot(self):
        import claude_shield.__main__ as main_mod

        fake_result = {
            "checks": [],
            "summary": {},
            "snapshot": {"System": {"MihomoProcessRunning": True}},
        }
        seen = {}

        def fake_format(checks, summary=None, lang="zh", compact=False, snapshot=None):
            seen["snapshot"] = snapshot
            return "ok"

        # __main__ imports format_report lazily via `from .report import format_report`
        import claude_shield.report as report_mod

        with patch.object(report_mod, "format_report", fake_format):
            out = main_mod._render_markdown(fake_result, lang="zh", compact=False)
        self.assertEqual(out, "ok")
        self.assertEqual(seen["snapshot"], fake_result["snapshot"])


if __name__ == "__main__":
    unittest.main()
