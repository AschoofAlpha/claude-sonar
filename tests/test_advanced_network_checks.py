import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from claude_shield.analyze import analyze_snapshot, run_full_audit


def _ids(checks):
    return {c.id: c for c in checks}


class TestAdvancedNetworkChecks(unittest.TestCase):

    def test_dns_respect_rules_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "DnsRespectRules": True}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_respect_rules"].status, "pass")

    def test_dns_respect_rules_warning(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "DnsRespectRules": False}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_respect_rules"].status, "warning")

    def test_dns_ipv6_consistent_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "DnsIPv6": False, "IPv6": False}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_ipv6"].status, "pass")

    def test_dns_ipv6_inconsistent_warning(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "DnsIPv6": True, "IPv6": False}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_ipv6"].status, "warning")

    def test_dns_encrypted_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "EncryptedDnsUpstreams": [
                {"Scheme": "https", "Host": "cloudflare-dns.com"},
                {"Scheme": "https", "Host": "dns.google"},
            ]}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_encrypted"].status, "pass")
        self.assertIn("Encrypted upstream", ids["network.dns_encrypted"].explanation)

    def test_dns_encrypted_empty_unknown(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "EncryptedDnsUpstreams": []}})
        ids = _ids(checks)
        # 1.2.0.dev0: conservative unknown when upstreams absent
        self.assertEqual(ids["network.dns_encrypted"].status, "unknown")

    def test_tun_stack_gvisor_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "TunStack": "gvisor"}})
        ids = _ids(checks)
        self.assertEqual(ids["network.tun_stack"].status, "pass")

    def test_tun_stack_other_unknown(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True, "TunStack": "system"}})
        ids = _ids(checks)
        # 1.2.0.dev0: conservative unknown for non-gvisor stacks
        self.assertEqual(ids["network.tun_stack"].status, "unknown")

    def test_policy_group_fixed_pass(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "PolicyGroups": {
                "SelectionAssessment": "FixedSelection",
                "RuntimeGroups": [{
                    "Name": "AI", "ReferencedByRule": True,
                    "UsesAutomaticSelection": False,
                    "SelectionChain": [
                        {"Name": "AI", "Type": "Selector", "Selected": "Node1"},
                        {"Name": "Node1", "Type": "Vless", "Selected": ""},
                    ],
                }],
            }}})
        ids = _ids(checks)
        self.assertEqual(ids["network.policy_group"].status, "pass")

    def test_policy_group_auto_selector_warning(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "PolicyGroups": {
                "SelectionAssessment": "FixedSelection",
                "RuntimeGroups": [{
                    "Name": "AI", "ReferencedByRule": True,
                    "UsesAutomaticSelection": False,
                    "SelectionChain": [
                        {"Name": "AI", "Type": "Selector", "Selected": "auto"},
                        {"Name": "auto", "Type": "URLTest", "Selected": ""},
                    ],
                }],
            }}})
        ids = _ids(checks)
        self.assertEqual(ids["network.policy_group"].status, "warning")
        self.assertIn("URLTest", ids["network.policy_group"].explanation)

    def test_policy_group_uses_automatic_warning(self):
        checks = analyze_snapshot({"Mihomo": {
            "AppConfigPresent": True,
            "PolicyGroups": {
                "SelectionAssessment": "FixedSelection",
                "RuntimeGroups": [{
                    "Name": "AI", "UsesAutomaticSelection": True, "SelectionChain": [],
                }],
            }}})
        ids = _ids(checks)
        self.assertEqual(ids["network.policy_group"].status, "warning")

    def test_dns_physical_resolver_warning(self):
        checks = analyze_snapshot({"System": {
            "LocalDnsServers": [
                {"Interface": "WLAN", "Family": 2, "Servers": ["218.85.157.99", "218.85.152.99"]},
            ]}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_physical_resolver"].status, "warning")
        # 1.2.0.dev0: redacted explanation omits raw IPs
        self.assertIn("non-local DNS resolver", ids["network.dns_physical_resolver"].explanation)

    def test_dns_physical_resolver_skips_tunnel(self):
        checks = analyze_snapshot({"System": {
            "LocalDnsServers": [
                {"Interface": "SSTAP 1", "Family": 2, "Servers": ["127.0.0.1"]},
            ]}})
        ids = _ids(checks)
        self.assertEqual(ids["network.dns_physical_resolver"].status, "pass")

    def test_run_full_audit_shape(self):
        try:
            result = run_full_audit(probe_timeout=3)
        except Exception as exc:
            self.fail(f"run_full_audit raised {type(exc).__name__}: {exc}")
        self.assertIn("checks", result)
        self.assertIn("summary", result)
        self.assertIn("snapshot", result)
        self.assertIsInstance(result["checks"], list)
        self.assertEqual(sum(result["summary"].values()), len(result["checks"]))


if __name__ == "__main__":
    unittest.main()
