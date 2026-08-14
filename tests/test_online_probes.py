"""Offline unit tests for online probes (reputation, cross-site, DNS).

All network and DNS calls are mocked — these tests must not touch the network.
"""

from __future__ import annotations

import inspect
import json
import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_sonar.probes.base import run_probes
from claude_sonar.probes.cross_site import check_cross_site_routing, DEFAULT_CROSS_SITE_URLS
from claude_sonar.probes.dns_probe import check_dns_consistency, DEFAULT_DNS_HOSTNAMES
from claude_sonar.probes.reputation import check_ip_reputation
from claude_sonar.redaction import Redactor


def _gai_ipv4(*_a, **_k):
    # (family, type, proto, canonname, sockaddr)
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
    ]


def _gai_dual(*_a, **_k):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
    ]


class TestRunProbesOffline(unittest.TestCase):
    def test_offline_returns_webrtc_guidance_only(self):
        # Cheap offline WebRTC guidance only — no network contact.
        for results in (run_probes(online=False), run_probes()):
            ids = [r.id for r in results]
            self.assertEqual(ids, ["browser.webrtc.guidance"])

    def test_signature_accepts_new_kwargs(self):
        params = inspect.signature(run_probes).parameters
        self.assertIn("online", params)
        self.assertIn("intended_region", params)
        self.assertIn("cross_site_urls", params)

    @patch("claude_sonar.probes.stability.check_egress_stability")
    @patch("claude_sonar.probes.egress.check_dual_stack_egress")
    @patch("claude_sonar.probes.cross_site.check_cross_site_routing")
    @patch("claude_sonar.probes.reputation.check_ip_reputation")
    @patch("claude_sonar.probes.dns_probe.check_dns_consistency")
    @patch("claude_sonar.probes.egress.check_egress_consistency")
    @patch("claude_sonar.probes.endpoints.get_all_endpoints")
    def test_online_wires_all_probes(
        self, mock_eps, mock_egress, mock_dns, mock_rep, mock_cross, mock_dual, mock_stab
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
        mock_rep.assert_called_once()
        self.assertEqual(mock_rep.call_args.kwargs.get("intended_region"), "US")
        mock_cross.assert_called_once()

    @patch("claude_sonar.probes.stability.check_egress_stability")
    @patch("claude_sonar.probes.egress.check_dual_stack_egress")
    @patch("claude_sonar.probes.cross_site.check_cross_site_routing")
    @patch("claude_sonar.probes.reputation.check_ip_reputation")
    @patch("claude_sonar.probes.dns_probe.check_dns_consistency")
    @patch("claude_sonar.probes.egress.check_egress_consistency")
    @patch("claude_sonar.probes.safety.validate_url")
    def test_custom_endpoint_without_online_skips_extended(
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
        self.assertNotIn("network.ip_reputation", ids)


class TestDnsProbe(unittest.TestCase):
    @patch("claude_sonar.probes.dns_probe.socket.getaddrinfo", side_effect=_gai_dual)
    def test_resolves_default_hosts_unknown_status(self, _mock):
        check = check_dns_consistency(timeout=1)
        self.assertEqual(check.id, "network.dns.consistency")
        self.assertEqual(check.status, "unknown")
        self.assertEqual(check.severity, "info")
        data = check.evidence[0].data
        self.assertEqual(data["unique_label_technique"], "not_used")
        hostnames = {r["hostname"] for r in data["resolutions"]}
        self.assertTrue(set(DEFAULT_DNS_HOSTNAMES).issubset(hostnames) or hostnames)
        for r in data["resolutions"]:
            self.assertTrue(r.get("ok"))
            self.assertIn("ipv4", r["address_families"])
            self.assertNotIn("addresses", r)
            self.assertFalse(r.get("raw_addresses_persisted", True) is True and "1.1.1.1" in str(r))

    @patch("claude_sonar.probes.dns_probe.socket.getaddrinfo", side_effect=socket.gaierror("boom"))
    def test_resolve_failure_still_unknown(self, _mock):
        check = check_dns_consistency(hostnames=["one.one.one.one"], timeout=1)
        self.assertEqual(check.status, "unknown")
        self.assertIn("Failed", check.explanation)

    @patch("claude_sonar.probes.dns_probe.socket.getaddrinfo", side_effect=_gai_ipv4)
    def test_no_raw_ip_in_explanation(self, _mock):
        check = check_dns_consistency(hostnames=["one.one.one.one"], timeout=1)
        self.assertNotIn("1.1.1.1", check.explanation)
        self.assertNotIn("1.1.1.1", json.dumps(check.evidence[0].data))


class TestReputationProbe(unittest.TestCase):
    def _ipapi_body(self, ip="203.0.113.10", country="US", asn="AS64500", org="Example Net"):
        return json.dumps({
            "ip": ip,
            "country_code": country,
            "country": country,
            "asn": asn,
            "org": org,
            "city": "Exampleville",
        })

    @patch("claude_sonar.probes.reputation.fetch_http")
    def test_success_pass_redacts_ip(self, mock_fetch):
        mock_fetch.return_value = (self._ipapi_body(), "direct_pinned")
        check = check_ip_reputation(timeout=2)
        self.assertEqual(check.id, "network.ip_reputation")
        self.assertEqual(check.status, "pass")
        self.assertNotIn("203.0.113.10", check.explanation)
        data = check.evidence[0].data
        self.assertEqual(data["country_code"], "US")
        self.assertEqual(data["asn"], "AS64500")
        self.assertTrue(str(data["observed_address"]).startswith("<IPV4:"))
        self.assertFalse(data["raw_value_persisted"])
        self.assertIn("not proof of account safety", check.explanation.lower())

    @patch("claude_sonar.probes.reputation.fetch_http")
    def test_intended_region_mismatch_unknown(self, mock_fetch):
        mock_fetch.return_value = (self._ipapi_body(country="JP"), "direct_pinned")
        check = check_ip_reputation(timeout=2, intended_region="US")
        self.assertEqual(check.status, "unknown")
        self.assertIn("US", check.explanation)

    @patch("claude_sonar.probes.reputation.fetch_http")
    def test_intended_region_match_pass(self, mock_fetch):
        mock_fetch.return_value = (self._ipapi_body(country="US"), "direct_pinned")
        check = check_ip_reputation(timeout=2, intended_region="us")
        self.assertEqual(check.status, "pass")

    @patch("claude_sonar.probes.reputation.fetch_http", side_effect=Exception("net down"))
    def test_fetch_failure_unknown(self, _mock):
        check = check_ip_reputation(timeout=1)
        self.assertEqual(check.status, "unknown")
        self.assertEqual(check.id, "network.ip_reputation")

    @patch("claude_sonar.probes.reputation.fetch_http")
    def test_ipinfo_org_asn_parsing(self, mock_fetch):
        body = json.dumps({
            "ip": "198.51.100.20",
            "country": "DE",
            "org": "AS3320 Deutsche Telekom AG",
        })
        mock_fetch.return_value = (body, "direct_pinned")
        check = check_ip_reputation(timeout=2)
        data = check.evidence[0].data
        self.assertEqual(data["country_code"], "DE")
        self.assertEqual(data["asn"], "AS3320")
        self.assertIn("Deutsche Telekom", data["org"])
        self.assertNotIn("198.51.100.20", check.explanation)


class TestCrossSiteProbe(unittest.TestCase):
    @patch("claude_sonar.probes.cross_site.validate_url", return_value=True)
    @patch("claude_sonar.probes.cross_site.fetch_http")
    def test_match_pass(self, mock_fetch, _val):
        mock_fetch.side_effect = [
            ("ip=203.0.113.50\n", "direct_pinned"),
            ("203.0.113.50", "direct_pinned"),
        ]
        check = check_cross_site_routing(timeout=2)
        self.assertEqual(check.id, "network.cross_site.routing")
        self.assertEqual(check.status, "pass")
        sites = check.evidence[0].data["sites"]
        self.assertEqual(len(sites), 2)
        self.assertEqual(sites[0]["observed_address"], sites[1]["observed_address"])
        self.assertNotIn("203.0.113.50", check.explanation)

    @patch("claude_sonar.probes.cross_site.validate_url", return_value=True)
    @patch("claude_sonar.probes.cross_site.fetch_http")
    def test_mismatch_warning(self, mock_fetch, _val):
        mock_fetch.side_effect = [
            ("ip=203.0.113.50\n", "direct_pinned"),
            ("198.51.100.9", "direct_pinned"),
        ]
        check = check_cross_site_routing(timeout=2)
        self.assertEqual(check.status, "warning")
        self.assertEqual(check.severity, "medium")

    @patch("claude_sonar.probes.cross_site.validate_url", return_value=True)
    @patch("claude_sonar.probes.cross_site.fetch_http", side_effect=Exception("fail"))
    def test_all_fail_unknown(self, _fetch, _val):
        check = check_cross_site_routing(timeout=1)
        self.assertEqual(check.status, "unknown")

    @patch("claude_sonar.probes.cross_site.validate_url", return_value=True)
    @patch("claude_sonar.probes.cross_site.fetch_http")
    def test_single_success_unknown(self, mock_fetch, _val):
        def side_effect(url, **kwargs):
            if "ipify" in url:
                return ("203.0.113.1", "direct_pinned")
            raise Exception("blocked")

        mock_fetch.side_effect = side_effect
        check = check_cross_site_routing(timeout=1)
        self.assertEqual(check.status, "unknown")

    def test_default_urls_are_https(self):
        for url in DEFAULT_CROSS_SITE_URLS:
            self.assertTrue(url.startswith("https://"))


class TestRedactorSharedAcrossSites(unittest.TestCase):
    def test_same_ip_same_token(self):
        r = Redactor()
        a = r.redact_ipv4("203.0.113.7")
        b = r.redact_ipv4("203.0.113.7")
        c = r.redact_ipv4("198.51.100.7")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


if __name__ == "__main__":
    unittest.main()
