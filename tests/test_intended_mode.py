"""Tests for intended_mode on TUN / default_route analysis."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot
from claude_sonar.analysis.system import normalize_intended_mode, merge_geo_with_egress
from claude_sonar.models import AuditCheck, Evidence


def _ids(checks):
    return {c.id: c for c in checks}


def _mihomo(tun_enabled, **extra):
    base = {
        "AppConfigPresent": True,
        "RuntimeConfigPresent": True,
        "Mode": "Rule",
        "AllowLan": False,
        "TunEnabled": tun_enabled,
        "StrictRoute": True,
        "DnsEnabled": True,
        "DnsMode": "fake-ip",
        "DnsHijackAny53": True,
    }
    base.update(extra)
    return base


class TestNormalizeIntendedMode(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(normalize_intended_mode("system_proxy"), "system_proxy")
        self.assertEqual(normalize_intended_mode("system-proxy"), "system_proxy")
        self.assertEqual(normalize_intended_mode("full_tunnel"), "full_tunnel")
        self.assertEqual(normalize_intended_mode("full-tunnel"), "full_tunnel")
        self.assertEqual(normalize_intended_mode("tun"), "full_tunnel")
        self.assertIsNone(normalize_intended_mode(None))
        self.assertIsNone(normalize_intended_mode(""))
        self.assertIsNone(normalize_intended_mode("banana"))


class TestTunIntendedMode(unittest.TestCase):
    def test_system_proxy_tun_off_pass(self):
        checks = analyze_snapshot(
            {"Mihomo": _mihomo(False)},
            intended_mode="system_proxy",
        )
        tun = _ids(checks)["network.tun"]
        self.assertEqual(tun.status, "pass")
        self.assertIn("system_proxy", tun.explanation)

    def test_system_proxy_alias_hyphen(self):
        checks = analyze_snapshot(
            {"Mihomo": _mihomo(False)},
            intended_mode="system-proxy",
        )
        self.assertEqual(_ids(checks)["network.tun"].status, "pass")

    def test_full_tunnel_tun_off_warning(self):
        checks = analyze_snapshot(
            {"Mihomo": _mihomo(False)},
            intended_mode="full_tunnel",
        )
        tun = _ids(checks)["network.tun"]
        self.assertEqual(tun.status, "warning")
        self.assertIn("full_tunnel", tun.explanation)
        self.assertTrue(tun.recommendation)

    def test_full_tunnel_alias_tun(self):
        checks = analyze_snapshot(
            {"Mihomo": _mihomo(False)},
            intended_mode="tun",
        )
        self.assertEqual(_ids(checks)["network.tun"].status, "warning")

    def test_full_tunnel_tun_on_pass(self):
        checks = analyze_snapshot(
            {"Mihomo": _mihomo(True)},
            intended_mode="full-tunnel",
        )
        tun = _ids(checks)["network.tun"]
        self.assertEqual(tun.status, "pass")
        self.assertIn("full_tunnel", tun.explanation)

    def test_none_tun_off_soft_unknown(self):
        checks = analyze_snapshot({"Mihomo": _mihomo(False)})
        tun = _ids(checks)["network.tun"]
        self.assertEqual(tun.status, "unknown")
        self.assertIn("intentional", tun.explanation.lower())


class TestDefaultRouteIntendedMode(unittest.TestCase):
    def test_full_tunnel_no_tunnel_default_warning(self):
        checks = analyze_snapshot(
            {
                "System": {
                    "DefaultRoute": {
                        "HasPhysicalDefault": True,
                        "HasTunnelDefault": False,
                        "PhysicalMetricLower": True,
                    }
                }
            },
            intended_mode="full_tunnel",
        )
        route = _ids(checks)["network.default_route"]
        self.assertEqual(route.status, "warning")
        self.assertIn("full_tunnel", route.explanation)

    def test_full_tunnel_tunnel_preferred_pass(self):
        checks = analyze_snapshot(
            {
                "System": {
                    "DefaultRoute": {
                        "HasPhysicalDefault": True,
                        "HasTunnelDefault": True,
                        "PhysicalMetricLower": False,
                    }
                }
            },
            intended_mode="full_tunnel",
        )
        self.assertEqual(_ids(checks)["network.default_route"].status, "pass")

    def test_system_proxy_physical_default_pass(self):
        checks = analyze_snapshot(
            {
                "System": {
                    "DefaultRoute": {
                        "HasPhysicalDefault": True,
                        "HasTunnelDefault": False,
                        "PhysicalMetricLower": True,
                    }
                }
            },
            intended_mode="system_proxy",
        )
        self.assertEqual(_ids(checks)["network.default_route"].status, "pass")

    def test_browser_secure_dns_dual_path_warning(self):
        checks = analyze_snapshot(
            {
                "System": {
                    "BrowserSecureDns": {"Chrome": "secure", "Edge": "off"},
                },
                "Mihomo": {
                    "AppConfigPresent": True,
                    "DnsEnabled": True,
                },
            }
        )
        doh = _ids(checks)["network.browser_secure_dns"]
        self.assertEqual(doh.status, "warning")
        self.assertIn("dual-path", doh.explanation.lower())

    def test_browser_secure_dns_off_pass(self):
        checks = analyze_snapshot(
            {
                "System": {
                    "BrowserSecureDns": {"Chrome": "off", "Edge": "off"},
                },
                "Mihomo": {
                    "AppConfigPresent": True,
                    "DnsEnabled": True,
                },
            }
        )
        self.assertEqual(_ids(checks)["network.browser_secure_dns"].status, "pass")


class TestMergeGeoWithEgress(unittest.TestCase):
    def test_merges_country_into_geo_stack(self):
        geo = AuditCheck(
            id="consistency.geo_stack",
            title="Geo stack",
            category="system",
            status="pass",
            severity="info",
            confidence="confirmed",
            explanation="TimeZone (UTC) and culture present. Offline informational only.",
            evidence=[Evidence(type="geo_stack", description="tz", data={"timezone": "UTC"})],
        )
        rep = AuditCheck(
            id="network.ip_reputation",
            title="rep",
            category="network",
            status="pass",
            severity="info",
            confidence="unknown",
            explanation="ok",
            evidence=[Evidence(
                type="ip_reputation",
                description="fields",
                data={"country_code": "SG"},
            )],
        )
        out = merge_geo_with_egress([geo, rep])
        self.assertIn("SG", out[0].explanation)
        self.assertIn("do not auto-follow", out[0].explanation.lower())


if __name__ == "__main__":
    unittest.main()
