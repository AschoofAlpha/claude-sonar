"""permissions.deny presence and Claude Desktop locale vs system UI languages."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot
from claude_sonar.report import classify_action


def _ids(checks):
    return {c.id: c for c in checks}


class TestSettingsDeny(unittest.TestCase):
    def test_deny_present_pass(self):
        row = _ids(analyze_snapshot({
            "ClaudeCode": {"SettingsJsonPresent": True, "SettingsDenyCount": 11}
        }))["privacy.settings_deny"]
        self.assertEqual(row.status, "pass")
        self.assertIn("11", row.explanation)
        self.assertEqual(classify_action(row), "leave_alone")

    def test_settings_missing_unknown(self):
        row = _ids(analyze_snapshot({
            "ClaudeCode": {"SettingsJsonPresent": False}
        }))["privacy.settings_deny"]
        self.assertEqual(row.status, "unknown")
        self.assertEqual(classify_action(row), "optional_consistency")

    def test_empty_deny_unknown(self):
        row = _ids(analyze_snapshot({
            "ClaudeCode": {"SettingsJsonPresent": True, "SettingsDenyCount": 0}
        }))["privacy.settings_deny"]
        self.assertEqual(row.status, "unknown")
        self.assertEqual(classify_action(row), "optional_consistency")


class TestDesktopLocale(unittest.TestCase):
    def test_config_matches_preferred_pass(self):
        row = _ids(analyze_snapshot({
            "System": {"PreferredUILanguages": ["en-US", "zh-Hans-SG"]},
            "ClaudeDesktop": {"ConfigPresent": True, "ConfigLocale": "en-US"},
        }))["system.desktop_locale"]
        self.assertEqual(row.status, "pass")

    def test_config_en_system_zh_warning(self):
        row = _ids(analyze_snapshot({
            "System": {"PreferredUILanguages": ["zh-CN"]},
            "ClaudeDesktop": {"ConfigPresent": True, "ConfigLocale": "en-US"},
        }))["system.desktop_locale"]
        self.assertEqual(row.status, "warning")
        self.assertIn("zh", row.explanation.lower())
        self.assertEqual(classify_action(row), "optional_consistency")

    def test_desktop_missing_unknown(self):
        row = _ids(analyze_snapshot({
            "System": {"PreferredUILanguages": ["en-US"]},
            "ClaudeDesktop": {"ConfigPresent": False},
        }))["system.desktop_locale"]
        self.assertEqual(row.status, "unknown")


if __name__ == "__main__":
    unittest.main()
