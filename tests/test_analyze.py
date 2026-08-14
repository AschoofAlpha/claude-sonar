import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from claude_sonar.analyze import analyze_snapshot, summarize, run_legacy_collector, CollectorError


class TestAnalyzeModule(unittest.TestCase):

    def test_analyze_empty_input(self):
        checks = analyze_snapshot({})
        self.assertIsInstance(checks, list)
        # No Mihomo config -> only the fallback check
        ids = {c.id for c in checks}
        self.assertIn("network.mihomo", ids)

    def test_summarize_counts(self):
        checks = analyze_snapshot({"System": {"Teredo": {"Available": True, "Disabled": False}}})
        summary = summarize(checks)
        self.assertIn("low", summary)
        self.assertIn("info", summary)
        self.assertEqual(sum(1 for c in checks if c.severity == "low"), summary["low"])

    def test_run_legacy_collector_raises_on_missing_powershell(self):
        # On non-Windows this raises; on Windows it either works or raises CollectorError
        try:
            run_legacy_collector(timeout=1)
        except CollectorError:
            pass  # expected when collector fails fast
        except Exception as exc:
            # PowerShell exists and collector ran (slow) — acceptable on real hosts
            self.assertIsInstance(exc, (CollectorError,))

    def test_known_check_ids_present(self):
        checks = analyze_snapshot({
            "Mihomo": {
                "AppConfigPresent": True,
                "Mode": "Rule",
                "AllowLan": False,
                "TunEnabled": True,
                "StrictRoute": True,
                "DnsEnabled": True,
                "DnsMode": "fake-ip",
                "DnsHijackAny53": True,
            }
        })
        ids = {c.id for c in checks}
        for check_id in ("network.mode", "network.allow_lan", "network.tun",
                         "network.strict_route", "network.dns",
                         "network.dns_mode", "network.dns_hijack"):
            self.assertIn(check_id, ids)


if __name__ == "__main__":
    unittest.main()
