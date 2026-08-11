"""Offline unit tests for extended online probes (dual-stack, stability, WebRTC, multi-DNS).

All network and DNS calls are mocked — these tests must not touch the network.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield.probes.base import run_probes
from claude_shield.probes.dns_probe import check_dns_consistency, DEFAULT_DNS_HOSTNAMES
from claude_shield.probes.egress import check_dual_stack_egress, observe_egress_url
from claude_shield.probes.stability import check_egress_stability
from claude_shield.probes.webrtc_guide import check_webrtc_guidance
from claude_shield.redaction import Redactor


def _gai_dual(*_a, **_k):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
    ]


def _gai_v4_only(host, port, family=0, type=0, proto=0, flags=0):
    if family == socket.AF_INET6:
        raise socket.gaierror("no v6")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]


class TestWebRtcGuidance(unittest.TestCase):
    def test_offline_guidance_unknown_info(self):
        check = check_webrtc_guidance()
        self.assertEqual(check.id, "browser.webrtc.guidance")
        self.assertEqual(check.status, "unknown")
        self.assertEqual(check.severity, "info")
        self.assertEqual(check.category, "browser")
        data = check.evidence[0].data
        self.assertFalse(data["auto_changed_browser_settings"])
        self.assertFalse(data["runtime_webrtc_exercised"])
        self.assertFalse(data["anti_detect_recommended"])
        self.assertFalse(data["fingerprint_spoof_recommended"])
        self.assertTrue(data["policy_hardening_only"])
        self.assertIn("manual", check.explanation.lower())
        self.assertIn("optional", check.recommendation.lower())
        # Guidance may mention anti-detect only to reject it.
        self.assertIn("do not install anti-detect", check.recommendation.lower())
        self.assertIn("policy", check.recommendation.lower())
        self.assertIn("will not apply", check.recommendation.lower())

    def test_run_probes_offline_includes_webrtc_only(self):
        results = run_probes(online=False)
        ids = [r.id for r in results]
        self.assertEqual(ids, ["browser.webrtc.guidance"])
        # No network probes offline
        self.assertNotIn("network.dns.consistency", ids)
        self.assertNotIn("network.ip_reputation", ids)
        self.assertNotIn("network.egress.stability", ids)
        self.assertNotIn("network.egress.dual_stack", ids)


class TestDnsMultiMethod(unittest.TestCase):
    @patch("claude_shield.probes.dns_probe.socket.getaddrinfo", side_effect=_gai_dual)
    def test_online_multi_method_classes(self, _mock):
        check = check_dns_consistency(timeout=1, online=True, hostnames=["one.one.one.one"])
        self.assertEqual(check.id, "network.dns.consistency")
        self.assertEqual(check.status, "unknown")
        data = check.evidence[0].data
        self.assertTrue(data["online_multi_method"])
        methods = {r["method"] for r in data["resolutions"]}
        self.assertIn("system_any", methods)
        self.assertIn("system_ipv4", methods)
        self.assertIn("system_ipv6", methods)
        for r in data["resolutions"]:
            self.assertIn("outcome_class", r)
            self.assertFalse(r.get("raw_addresses_persisted", True))
            blob = json.dumps(r)
            self.assertNotIn("1.1.1.1", blob)
            self.assertNotIn("2606:4700", blob)
        self.assertIn("dual_stack", data["outcome_classes"] or ["dual_stack"])

    @patch("claude_shield.probes.dns_probe.socket.getaddrinfo", side_effect=_gai_v4_only)
    def test_offline_single_method(self, _mock):
        check = check_dns_consistency(timeout=1, online=False, hostnames=["one.one.one.one"])
        data = check.evidence[0].data
        methods = {r["method"] for r in data["resolutions"]}
        self.assertEqual(methods, {"system_any"})
        self.assertEqual(check.status, "unknown")

    @patch("claude_shield.probes.dns_probe.socket.getaddrinfo", side_effect=_gai_dual)
    def test_default_hosts_still_used(self, _mock):
        check = check_dns_consistency(timeout=1, online=True)
        hostnames = {r["hostname"] for r in check.evidence[0].data["resolutions"]}
        self.assertTrue(set(DEFAULT_DNS_HOSTNAMES).issubset(hostnames))


class TestDualStackEgress(unittest.TestCase):
    @patch("claude_shield.probes.egress._reputation_classes", return_value=("US", "AS64500", None))
    @patch("claude_shield.probes.egress.run_python_probe")
    def test_both_families_pass(self, mock_probe, _rep):
        def side_effect(url, timeout, is_custom=False):
            if "api6" in url:
                return ("2001:db8::1", "direct_pinned")
            return ("203.0.113.10", "direct_pinned")

        mock_probe.side_effect = side_effect
        check = check_dual_stack_egress(timeout=4)
        self.assertEqual(check.id, "network.egress.dual_stack")
        self.assertEqual(check.status, "pass")
        data = check.evidence[0].data
        self.assertIn("ipv4", data["families_observed"])
        self.assertIn("ipv6", data["families_observed"])
        self.assertEqual(data["country_class"], "US")
        self.assertEqual(data["asn_class"], "AS64500")
        self.assertNotIn("203.0.113.10", check.explanation)
        self.assertNotIn("2001:db8::1", check.explanation)
        self.assertTrue(str(data["ipv4"]["observed_address"]).startswith("<IPV4:"))
        self.assertTrue(str(data["ipv6"]["observed_address"]).startswith("<IPV6:"))

    @patch("claude_shield.probes.egress._reputation_classes", return_value=(None, None, "unavailable"))
    @patch("claude_shield.probes.egress.run_python_probe")
    def test_v6_unavailable_unknown_not_fail(self, mock_probe, _rep):
        def side_effect(url, timeout, is_custom=False):
            if "api6" in url:
                return (None, "unavailable")
            return ("198.51.100.20", "direct_pinned")

        mock_probe.side_effect = side_effect
        check = check_dual_stack_egress(timeout=3)
        self.assertEqual(check.status, "unknown")
        self.assertNotEqual(check.status, "fail")
        self.assertIn("IPv6", check.explanation)
        self.assertIn("unknown", check.explanation.lower())

    @patch("claude_shield.probes.egress._reputation_classes", return_value=(None, None, "unavailable"))
    @patch("claude_shield.probes.egress.run_python_probe", return_value=(None, "unavailable"))
    def test_both_unavailable_unknown(self, _probe, _rep):
        check = check_dual_stack_egress(timeout=2)
        self.assertEqual(check.status, "unknown")
        self.assertEqual(check.confidence, "unknown")

    @patch("claude_shield.probes.egress.run_python_probe")
    def test_observe_egress_url_redacts(self, mock_probe):
        mock_probe.return_value = ("203.0.113.99", "direct_pinned")
        r = Redactor()
        obs = observe_egress_url("https://api.ipify.org", timeout=1, redactor=r, expected_family="ipv4")
        self.assertTrue(obs["ok"])
        self.assertEqual(obs["address_family"], "ipv4")
        self.assertTrue(obs["observed_address"].startswith("<IPV4:"))
        self.assertFalse(obs["raw_value_persisted"])


class TestEgressStability(unittest.TestCase):
    def _sample(self, country, asn, ok=True):
        return {
            "ok": ok,
            "error": None if ok else "unavailable",
            "country_class": country,
            "asn_class": asn,
            "address_family": "ipv4",
            "observed_address": "<IPV4:deadbe>",
            "source": "ipapi.co",
            "raw_value_persisted": False,
        }

    @patch("claude_shield.probes.stability._sample_classes")
    def test_stable_classes_pass(self, mock_sample):
        mock_sample.side_effect = [
            self._sample("US", "AS64500"),
            self._sample("US", "AS64500"),
        ]
        check = check_egress_stability(timeout=4, delay_s=0, sleeper=lambda _s: None)
        self.assertEqual(check.id, "network.egress.stability")
        self.assertEqual(check.status, "pass")
        self.assertIn("stable", check.explanation.lower())
        self.assertIn("not proof", check.explanation.lower())
        self.assertIn("ban risk", check.explanation.lower())  # denied, not claimed

    @patch("claude_shield.probes.stability._sample_classes")
    def test_class_change_warning(self, mock_sample):
        mock_sample.side_effect = [
            self._sample("US", "AS64500"),
            self._sample("JP", "AS2516"),
        ]
        check = check_egress_stability(timeout=4, delay_s=0, sleeper=lambda _s: None)
        self.assertEqual(check.status, "warning")
        self.assertEqual(check.severity, "medium")
        self.assertIn("changed", check.explanation.lower())
        self.assertIn("not a ban-risk", check.explanation.lower())

    @patch("claude_shield.probes.stability._sample_classes")
    def test_insufficient_samples_unknown(self, mock_sample):
        mock_sample.side_effect = [
            self._sample(None, None, ok=False),
            self._sample("US", "AS64500"),
        ]
        check = check_egress_stability(timeout=3, delay_s=0, sleeper=lambda _s: None)
        self.assertEqual(check.status, "unknown")

    @patch("claude_shield.probes.stability._sample_classes")
    def test_no_sleep_when_delay_zero(self, mock_sample):
        calls = []
        mock_sample.side_effect = [
            self._sample("DE", "AS3320"),
            self._sample("DE", "AS3320"),
        ]

        def track_sleep(s):
            calls.append(s)

        check = check_egress_stability(timeout=2, delay_s=0, sleeper=track_sleep)
        self.assertEqual(check.status, "pass")
        self.assertEqual(calls, [])


class TestRunProbesWiringExt(unittest.TestCase):
    @patch("claude_shield.probes.stability.check_egress_stability")
    @patch("claude_shield.probes.egress.check_dual_stack_egress")
    @patch("claude_shield.probes.cross_site.check_cross_site_routing")
    @patch("claude_shield.probes.reputation.check_ip_reputation")
    @patch("claude_shield.probes.dns_probe.check_dns_consistency")
    @patch("claude_shield.probes.egress.check_egress_consistency")
    @patch("claude_shield.probes.endpoints.get_all_endpoints")
    def test_online_wires_extended(
        self,
        mock_eps,
        mock_egress,
        mock_dns,
        mock_rep,
        mock_cross,
        mock_dual,
        mock_stab,
    ):
        mock_eps.return_value = [{
            "id": "ipify-ipv4",
            "purpose": "public-egress-observation",
            "url": "https://api.ipify.org",
            "enabled": True,
            "supports_ipv4": True,
            "supports_ipv6": False,
            "expected_content_type": "text/plain",
            "maximum_response_bytes": 1024,
        }]
        mock_egress.return_value = MagicMock(id="network.egress.runtime_consistency.ipify-ipv4")
        mock_dns.return_value = MagicMock(id="network.dns.consistency")
        mock_rep.return_value = MagicMock(id="network.ip_reputation")
        mock_cross.return_value = MagicMock(id="network.cross_site.routing")
        mock_dual.return_value = MagicMock(id="network.egress.dual_stack")
        mock_stab.return_value = MagicMock(id="network.egress.stability")

        results = run_probes(online=True, timeout=3, intended_region="US")
        ids = [r.id for r in results]
        self.assertIn("browser.webrtc.guidance", ids)
        self.assertIn("network.dns.consistency", ids)
        self.assertIn("network.ip_reputation", ids)
        self.assertIn("network.cross_site.routing", ids)
        self.assertIn("network.egress.dual_stack", ids)
        self.assertIn("network.egress.stability", ids)
        mock_dns.assert_called_once()
        self.assertTrue(mock_dns.call_args.kwargs.get("online") is True)
        mock_dual.assert_called_once()
        mock_stab.assert_called_once()

    @patch("claude_shield.probes.stability.check_egress_stability")
    @patch("claude_shield.probes.egress.check_dual_stack_egress")
    @patch("claude_shield.probes.cross_site.check_cross_site_routing")
    @patch("claude_shield.probes.reputation.check_ip_reputation")
    @patch("claude_shield.probes.dns_probe.check_dns_consistency")
    @patch("claude_shield.probes.egress.check_egress_consistency")
    @patch("claude_shield.probes.safety.validate_url")
    def test_custom_without_online_skips_extended(
        self, mock_val, mock_egress, mock_dns, mock_rep, mock_cross, mock_dual, mock_stab
    ):
        mock_val.return_value = True
        mock_egress.return_value = MagicMock(id="network.egress.runtime_consistency.custom")
        mock_dns.return_value = MagicMock(id="network.dns.consistency")

        results = run_probes(
            custom_endpoint="https://api.ipify.org",
            online=False,
            timeout=3,
        )
        ids = [r.id for r in results]
        self.assertIn("browser.webrtc.guidance", ids)
        self.assertIn("network.dns.consistency", ids)
        mock_rep.assert_not_called()
        mock_cross.assert_not_called()
        mock_dual.assert_not_called()
        mock_stab.assert_not_called()
        # DNS online flag false on custom-only path
        self.assertFalse(mock_dns.call_args.kwargs.get("online"))


if __name__ == "__main__":
    unittest.main()
