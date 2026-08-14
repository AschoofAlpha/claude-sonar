import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_sonar.analyze import analyze_snapshot
from claude_sonar.analysis.mihomo import _normalize_encrypted_upstreams


def _ids(checks):
    return {c.id: c for c in checks}


class TestEncryptedDns(unittest.TestCase):
    def test_normalize_list_shape(self):
        schemes = _normalize_encrypted_upstreams([
            {"Scheme": "https"},
            {"Scheme": "tls"},
            {"Scheme": "https"},
        ])
        self.assertEqual(schemes, ["https", "tls"])

    def test_normalize_dict_shape(self):
        schemes = _normalize_encrypted_upstreams({"Scheme": "https"})
        self.assertEqual(schemes, ["https"])

    def test_normalize_empty_list(self):
        self.assertEqual(_normalize_encrypted_upstreams([]), [])

    def test_normalize_none(self):
        self.assertEqual(_normalize_encrypted_upstreams(None), [])

    def test_normalize_ignores_non_dict(self):
        self.assertEqual(_normalize_encrypted_upstreams(["https", 1, None]), [])

    def test_dns_encrypted_list_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "EncryptedDnsUpstreams": [
                {"Scheme": "https", "Host": "cloudflare-dns.com"},
                {"Scheme": "h3"},
            ],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_encrypted"].status, "pass")
        self.assertIn("https", ids["network.dns_encrypted"].explanation)
        self.assertIn("h3", ids["network.dns_encrypted"].explanation)
        self.assertTrue(ids["network.dns_encrypted"].evidence)

    def test_dns_encrypted_dict_shape_pass(self):
        """PowerShell ConvertTo-Json may collapse a single upstream to a dict."""
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "EncryptedDnsUpstreams": {"Scheme": "https"},
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_encrypted"].status, "pass")
        self.assertIn("https", ids["network.dns_encrypted"].explanation)

    def test_dns_encrypted_tls_and_quic(self):
        for scheme in ("tls", "quic", "h3"):
            checks = analyze_snapshot({"Mihomo": {
                "AppConfigPresent": True,
                "EncryptedDnsUpstreams": {"Scheme": scheme},
            }})
            ids = _ids(checks)
            self.assertEqual(
                ids["network.dns_encrypted"].status,
                "pass",
                msg=f"scheme={scheme}",
            )
            self.assertIn(scheme, ids["network.dns_encrypted"].explanation)

    def test_dns_encrypted_empty_unknown(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "EncryptedDnsUpstreams": [],
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_encrypted"].status, "unknown")

    def test_dns_encrypted_dict_without_scheme_unknown(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "EncryptedDnsUpstreams": {"Host": "example.com"},
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_encrypted"].status, "unknown")

    def test_tun_off_is_unknown_not_warning(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "TunEnabled": False,
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.tun"].status, "unknown")
        self.assertEqual(ids["network.tun"].severity, "info")
        self.assertIn("intentional", ids["network.tun"].explanation.lower())

    def test_tun_on_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "TunEnabled": True,
        }})
        ids = _ids(checks)
        self.assertEqual(ids["network.tun"].status, "pass")


if __name__ == "__main__":
    unittest.main()
