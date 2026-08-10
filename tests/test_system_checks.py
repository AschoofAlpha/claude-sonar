import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from claude_shield.analyze import analyze_snapshot


def _ids(checks):
    return {c.id: c for c in checks}


class TestSystemLevelChecks(unittest.TestCase):

    def test_service_mode_full_pass(self):
        checks = analyze_snapshot({"System": {
            "MihomoProcessRunning": True,
            "ServiceModeActive": True,
            "MixedPortListening": True,
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.service"].status, "pass")
        self.assertTrue(ids["network.service"].evidence)

    def test_service_mode_partial_warning(self):
        checks = analyze_snapshot({"System": {
            "MihomoProcessRunning": True,
            "ServiceModeActive": False,
            "MixedPortListening": False,
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.service"].status, "warning")
        self.assertEqual(ids["network.service"].severity, "low")

    def test_service_mode_none_unknown(self):
        checks = analyze_snapshot({"System": {
            "MihomoProcessRunning": False,
            "ServiceModeActive": False,
            "MixedPortListening": False,
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.service"].status, "unknown")

    def test_teredo_disabled_pass(self):
        checks = analyze_snapshot({"System": {
            "Teredo": {"Available": True, "Type": "Disabled", "Disabled": True},
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.teredo"].status, "pass")

    def test_teredo_enabled_warning(self):
        checks = analyze_snapshot({"System": {
            "Teredo": {"Available": True, "Type": "Client", "Disabled": False},
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.teredo"].status, "warning")

    def test_ipv6_binding_no_physical_enabled_pass(self):
        checks = analyze_snapshot({"System": {
            "ActiveAdapterIPv6Bindings": [
                {"Interface": "vEthernet", "Classification": "VirtualOrOther", "Enabled": True},
                {"Interface": "Realtek", "Classification": "Physical", "Enabled": False},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.ipv6_binding"].status, "pass")

    def test_ipv6_binding_physical_enabled_warning(self):
        checks = analyze_snapshot({"System": {
            "ActiveAdapterIPv6Bindings": [
                {"Interface": "Realtek", "Classification": "Physical", "Enabled": True},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.ipv6_binding"].status, "warning")

    def test_env_proxy_present_unknown(self):
        checks = analyze_snapshot({"System": {
            "ProxyEnvironmentVariables": [
                {"Scope": "Process", "Name": "HTTP_PROXY", "Present": True},
                {"Scope": "User", "Name": "NO_PROXY", "Present": True},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.env_proxy"].status, "unknown")
        self.assertIn("HTTP_PROXY", ids["network.env_proxy"].explanation)
        self.assertIn("NO_PROXY", ids["network.env_proxy"].explanation)
        # values must never appear in the explanation
        self.assertNotIn("://", ids["network.env_proxy"].explanation)
        self.assertIn("not shown", ids["network.env_proxy"].explanation.lower())
        self.assertIn("system_proxy", ids["network.env_proxy"].explanation)

    def test_env_proxy_absent_pass(self):
        checks = analyze_snapshot({"System": {
            "ProxyEnvironmentVariables": [
                {"Scope": "Process", "Name": "HTTP_PROXY", "Present": False},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.env_proxy"].status, "pass")

    def test_locale_consistent_pass(self):
        checks = analyze_snapshot({"System": {
            "Culture": "en-US",
            "UICulture": "en-US",
            "SystemLocale": "en-US",
            "UserLanguageList": ["en-US", "zh-Hans-SG"],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["system.locale"].status, "pass")
        self.assertTrue(ids["system.locale"].evidence)

    def test_locale_mismatch_warning_optional_only(self):
        checks = analyze_snapshot({"System": {
            "Culture": "en-US",
            "UICulture": "en-GB",
            "SystemLocale": "zh-CN",
            "UserLanguageList": ["ja-JP"],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["system.locale"].status, "warning")
        self.assertEqual(ids["system.locale"].severity, "info")
        # bilingual / mismatch is optional consistency, not a hard fail
        self.assertNotEqual(ids["system.locale"].status, "fail")

    def test_timezone_present_pass(self):
        checks = analyze_snapshot({"System": {
            "TimeZone": "China Standard Time",
        }})
        ids = _ids(checks)
        self.assertIn("system.timezone", ids)
        self.assertEqual(ids["system.timezone"].status, "pass")
        self.assertIn("China Standard Time", ids["system.timezone"].explanation)
        self.assertTrue(ids["system.timezone"].evidence)

    def test_timezone_missing_unknown(self):
        checks = analyze_snapshot({"System": {
            "Culture": "en-US",
        }})
        ids = _ids(checks)
        self.assertIn("system.timezone", ids)
        self.assertEqual(ids["system.timezone"].status, "unknown")
        self.assertIn("missing", ids["system.timezone"].explanation.lower())

    def test_timezone_empty_unknown(self):
        checks = analyze_snapshot({"System": {
            "TimeZone": "",
        }})
        ids = _ids(checks)
        self.assertEqual(ids["system.timezone"].status, "unknown")

    def test_system_checks_run_without_mihomo(self):
        # Regression: system checks must run even when Mihomo config is absent
        checks = analyze_snapshot({"System": {
            "Teredo": {"Available": True, "Disabled": True},
            "TimeZone": "UTC",
        }})
        ids = _ids(checks)
        self.assertIn("network.teredo", ids)
        self.assertIn("network.mihomo", ids)
        self.assertIn("system.timezone", ids)
        self.assertEqual(ids["network.mihomo"].status, "unknown")

    def test_privacy_not_configured_prefix(self):
        checks = analyze_snapshot({"ClaudeCode": {}})
        ids = _ids(checks)
        self.assertIn("[not_configured]", ids["privacy.prompt_history"].explanation)
        self.assertIn("[not_configured]", ids["privacy.telemetry"].explanation)

    def test_known_ids_unchanged(self):
        # Existing Mihomo checks keep their ids when config is present
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "Mode": "Rule",
            "AllowLan": False,
            "TunEnabled": True,
            "StrictRoute": True,
            "DnsEnabled": True,
            "DnsMode": "fake-ip",
            "DnsHijackAny53": True,
        }})
        ids = _ids(checks)
        for check_id in ("network.mode", "network.allow_lan", "network.tun",
                         "network.strict_route", "network.dns",
                         "network.dns_mode", "network.dns_hijack"):
            self.assertIn(check_id, ids)


if __name__ == "__main__":
    unittest.main()
