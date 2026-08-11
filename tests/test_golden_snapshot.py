"""Golden minimal Windows snapshot — stable check-id subset."""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_shield.analyze import analyze_snapshot

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "windows_snapshot_min.json"

# Stable core IDs expected from the minimal golden snapshot (subset assert).
EXPECTED_SUBSET = frozenset({
    "privacy.telemetry",
    "privacy.errors",
    "privacy.nonessential",
    "privacy.prompt_history",
    "privacy.subprocess_scrub",
    "privacy.otel_user_prompts",
    "privacy.otel_tool_content",
    "privacy.otel_tool_details",
    "privacy.otel_raw_api",
    "privacy.local_device_id",
    "privacy.telemetry_cache",
    "network.service",
    "network.teredo",
    "network.ipv6_binding",
    "network.dns_physical_resolver",
    "network.env_proxy",
    "network.system_proxy",
    "network.proxy_autoconfig",
    "network.proxy_layers",
    "network.default_route",
    "network.browser_secure_dns",
    "network.other_proxy_clients",
    "system.locale",
    "system.timezone",
    "consistency.geo_stack",
    "network.mode",
    "network.allow_lan",
    "network.tun",
    "network.strict_route",
    "network.dns",
    "network.dns_mode",
    "network.dns_hijack",
})


class TestGoldenSnapshot(unittest.TestCase):
    def test_fixture_loads(self):
        self.assertTrue(FIXTURE.is_file(), msg=f"missing fixture {FIXTURE}")
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertIn("System", data)
        self.assertIn("Mihomo", data)
        self.assertIn("DefaultRoute", data["System"])
        self.assertIn("BrowserSecureDns", data["System"])

    def test_analyze_produces_stable_id_subset(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        checks = analyze_snapshot(data, intended_mode="full_tunnel")
        ids = {c.id for c in checks}
        missing = EXPECTED_SUBSET - ids
        self.assertFalse(missing, msg=f"missing check ids: {sorted(missing)}")

    def test_golden_statuses_smoke(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        checks = analyze_snapshot(data, intended_mode="full_tunnel")
        by_id = {c.id: c for c in checks}
        self.assertEqual(by_id["network.tun"].status, "pass")
        self.assertEqual(by_id["network.default_route"].status, "pass")
        self.assertEqual(by_id["network.browser_secure_dns"].status, "pass")
        self.assertEqual(by_id["consistency.geo_stack"].status, "pass")
        self.assertIn("[folded_optional]", by_id["privacy.prompt_history"].explanation)


if __name__ == "__main__":
    unittest.main()
