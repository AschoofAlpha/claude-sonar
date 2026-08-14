"""Synthetic-snapshot tests for proxy layers, env_proxy, PAC/WPAD, geo_stack."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot


def _ids(checks):
    return {c.id: c for c in checks}


def _base_system(**extra):
    data = {
        "SystemProxy": {"Enabled": True, "PointsToLoopback": True, "PortLooksLikeMixed": True},
        "WinHttpProxy": {"Enabled": False, "PointsToLoopback": False, "HasProxyList": False},
        "ProxyAutoConfig": {"AutoDetect": False, "AutoConfigURLPresent": False},
        "ProxyEnvironmentVariables": [],
        "TimeZone": "China Standard Time",
        "Culture": "zh-CN",
        "UICulture": "zh-CN",
        "SystemLocale": "zh-CN",
    }
    data.update(extra)
    return {"System": data}


class TestEnvProxyImproved(unittest.TestCase):
    def test_env_only_without_system_proxy_unknown(self):
        checks = analyze_snapshot({"System": {
            "ProxyEnvironmentVariables": [
                {"Scope": "Process", "Name": "HTTP_PROXY", "Present": True},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.env_proxy"].status, "unknown")
        self.assertIn("HTTP_PROXY", ids["network.env_proxy"].explanation)
        self.assertNotIn("://", ids["network.env_proxy"].explanation)
        self.assertIn("not shown", ids["network.env_proxy"].explanation.lower())

    def test_env_alongside_loopback_system_proxy_pass(self):
        checks = analyze_snapshot(_base_system(
            ProxyEnvironmentVariables=[
                {"Scope": "User", "Name": "HTTPS_PROXY", "Present": True},
                {"Scope": "User", "Name": "NO_PROXY", "Present": True},
            ],
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.env_proxy"].status, "pass")
        self.assertIn("alongside", ids["network.env_proxy"].explanation.lower())
        self.assertIn("HTTPS_PROXY", ids["network.env_proxy"].explanation)
        self.assertNotIn("://", ids["network.env_proxy"].explanation)
        self.assertNotIn("127.0.0.1", ids["network.env_proxy"].explanation)

    def test_env_absent_pass(self):
        checks = analyze_snapshot(_base_system())
        ids = _ids(checks)
        self.assertEqual(ids["network.env_proxy"].status, "pass")
        self.assertIn("No proxy environment", ids["network.env_proxy"].explanation)


class TestProxyLayers(unittest.TestCase):
    def test_system_loopback_winhttp_direct_pass(self):
        checks = analyze_snapshot(_base_system())
        ids = _ids(checks)
        self.assertIn("network.proxy_layers", ids)
        self.assertEqual(ids["network.proxy_layers"].status, "pass")
        self.assertIn("loopback", ids["network.proxy_layers"].explanation.lower())
        self.assertTrue(ids["network.proxy_layers"].evidence)

    def test_system_and_winhttp_both_loopback_pass(self):
        checks = analyze_snapshot(_base_system(
            WinHttpProxy={"Enabled": True, "PointsToLoopback": True, "HasProxyList": True},
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_layers"].status, "pass")
        self.assertIn("WinHTTP loopback", ids["network.proxy_layers"].explanation)

    def test_winhttp_non_loopback_conflicts_warning(self):
        checks = analyze_snapshot(_base_system(
            WinHttpProxy={"Enabled": True, "PointsToLoopback": False, "HasProxyList": True},
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_layers"].status, "warning")
        self.assertIn("WinHTTP", ids["network.proxy_layers"].explanation)
        rec = ids["network.proxy_layers"].recommendation or ""
        # Advisory verbs only when recommendations are included; analyze may strip them.
        # Status/explanation must still warn.
        self.assertNotIn("will change", (ids["network.proxy_layers"].explanation + rec).lower())

    def test_pac_with_system_proxy_warning(self):
        checks = analyze_snapshot(_base_system(
            ProxyAutoConfig={"AutoDetect": True, "AutoConfigURLPresent": False},
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_layers"].status, "warning")
        self.assertIn("PAC/WPAD", ids["network.proxy_layers"].explanation)

    def test_autoconfig_url_with_system_proxy_warning(self):
        checks = analyze_snapshot(_base_system(
            ProxyAutoConfig={"AutoDetect": False, "AutoConfigURLPresent": True},
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_layers"].status, "warning")
        self.assertEqual(ids["network.proxy_autoconfig"].status, "warning")
        # Never leak a PAC URL / IP
        for cid in ("network.proxy_layers", "network.proxy_autoconfig"):
            text = ids[cid].explanation
            self.assertNotIn("http", text.lower().replace("wpad", "").replace("pac", "x"))
            self.assertNotIn("://", text)

    def test_incomplete_layers_unknown(self):
        checks = analyze_snapshot({"System": {
            "WinHttpProxy": {},
            "ProxyAutoConfig": {},
        }})
        ids = _ids(checks)
        self.assertIn("network.proxy_layers", ids)
        self.assertEqual(ids["network.proxy_layers"].status, "unknown")

    def test_system_proxy_non_loopback_warning(self):
        checks = analyze_snapshot(_base_system(
            SystemProxy={"Enabled": True, "PointsToLoopback": False},
            WinHttpProxy={"Enabled": False, "PointsToLoopback": False, "HasProxyList": False},
            ProxyAutoConfig={"AutoDetect": False, "AutoConfigURLPresent": False},
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_layers"].status, "warning")
        self.assertNotIn("127.0.0.1", ids["network.proxy_layers"].explanation)


class TestProxyAutoconfig(unittest.TestCase):
    def test_pac_off_pass(self):
        checks = analyze_snapshot(_base_system())
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_autoconfig"].status, "pass")

    def test_wpad_on_warning(self):
        checks = analyze_snapshot(_base_system(
            ProxyAutoConfig={"AutoDetect": True, "AutoConfigURLPresent": False},
        ))
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_autoconfig"].status, "warning")
        self.assertIn("AutoDetect", ids["network.proxy_autoconfig"].explanation)
        rec = (ids["network.proxy_autoconfig"].recommendation or "").lower()
        expl = ids["network.proxy_autoconfig"].explanation.lower()
        self.assertTrue("consider" in rec or "confirm" in expl)

    def test_partial_autoconfig_no_pac_pass(self):
        # Missing AutoDetect registry value + no PAC URL => treat as pass (common on Windows).
        checks = analyze_snapshot({"System": {
            "ProxyAutoConfig": {"AutoDetect": None, "AutoConfigURLPresent": False},
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.proxy_autoconfig"].status, "pass")
        self.assertIn("No PAC URL", ids["network.proxy_autoconfig"].explanation)


class TestGeoStack(unittest.TestCase):
    def test_geo_stack_pass_when_tz_and_culture_present(self):
        checks = analyze_snapshot(_base_system())
        ids = _ids(checks)
        self.assertIn("consistency.geo_stack", ids)
        self.assertEqual(ids["consistency.geo_stack"].status, "pass")
        self.assertIn("China Standard Time", ids["consistency.geo_stack"].explanation)
        rec = ids["consistency.geo_stack"].recommendation or ""
        blob = (ids["consistency.geo_stack"].explanation + " " + rec).lower()
        self.assertIn("truthful", blob)
        self.assertNotIn("change timezone to match", blob)
        self.assertNotIn("set timezone to", blob)
        # Must not push node-country following
        self.assertIn("do not auto-follow", blob)

    def test_geo_stack_warning_when_locale_mismatched(self):
        checks = analyze_snapshot(_base_system(
            Culture="en-US",
            UICulture="zh-CN",
            SystemLocale="zh-CN",
        ))
        ids = _ids(checks)
        self.assertEqual(ids["system.locale"].status, "warning")
        self.assertEqual(ids["consistency.geo_stack"].status, "warning")
        rec = (ids["consistency.geo_stack"].recommendation or "").lower()
        self.assertTrue(
            "consider" in rec or "optional" in rec or "truthful" in rec,
            msg=f"recommendation not advisory: {rec!r}",
        )
        self.assertNotIn("will change", rec)

    def test_geo_stack_partial_unknown(self):
        checks = analyze_snapshot({"System": {
            "TimeZone": "UTC",
        }})
        ids = _ids(checks)
        self.assertEqual(ids["consistency.geo_stack"].status, "unknown")
        self.assertIn("partial", ids["consistency.geo_stack"].explanation.lower())

    def test_geo_stack_missing_unknown(self):
        checks = analyze_snapshot({"System": {
            "MihomoProcessRunning": False,
        }})
        ids = _ids(checks)
        self.assertEqual(ids["consistency.geo_stack"].status, "unknown")


class TestOtherProxyClientsExpanded(unittest.TestCase):
    def test_named_clients_in_explanation(self):
        checks = analyze_snapshot({"System": {
            "OtherProxyClientCount": 2,
            "OtherProxyClientsRunning": [
                {"Name": "v2rayN", "Running": True},
                {"Name": "hysteria2", "Running": True},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.other_proxy_clients"].status, "unknown")
        self.assertIn("v2rayN", ids["network.other_proxy_clients"].explanation)
        self.assertIn("hysteria2", ids["network.other_proxy_clients"].explanation)


class TestExistingIdsStillPresent(unittest.TestCase):
    def test_core_ids_with_full_snapshot(self):
        checks = analyze_snapshot(_base_system(
            MihomoProcessRunning=True,
            ServiceModeActive=True,
            MixedPortListening=True,
            OtherProxyClientCount=0,
        ))
        ids = _ids(checks)
        for check_id in (
            "network.env_proxy",
            "network.system_proxy",
            "network.proxy_layers",
            "network.proxy_autoconfig",
            "network.other_proxy_clients",
            "system.locale",
            "system.timezone",
            "consistency.geo_stack",
        ):
            self.assertIn(check_id, ids)


if __name__ == "__main__":
    unittest.main()
