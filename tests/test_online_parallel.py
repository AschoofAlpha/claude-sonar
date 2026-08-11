"""Mocked tests for parallel online probe execution in probes.base."""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_shield.probes import base as probes_base
from claude_shield.probes.base import _run_online_probes_parallel, run_probes


class TestOnlineParallelHelper(unittest.TestCase):
    def test_preserves_order(self):
        barrier = threading.Barrier(5)
        order_started = []
        lock = threading.Lock()

        def make_job(name, delay):
            def _fn():
                with lock:
                    order_started.append(name)
                # Stagger completion so as_completed would reverse order without sorting.
                time.sleep(delay)
                try:
                    barrier.wait(timeout=2)
                except Exception:
                    pass
                return f"ok:{name}"

            return _fn

        # Later jobs finish first if delays inverted.
        jobs = [
            ("dns", make_job("dns", 0.05)),
            ("reputation", make_job("reputation", 0.04)),
            ("cross_site", make_job("cross_site", 0.03)),
            ("dual_stack", make_job("dual_stack", 0.02)),
            ("stability", make_job("stability", 0.01)),
        ]
        results = _run_online_probes_parallel(jobs)
        self.assertEqual(
            results,
            ["ok:dns", "ok:reputation", "ok:cross_site", "ok:dual_stack", "ok:stability"],
        )

    def test_fallback_sequential_on_worker_error(self):
        calls = []

        def ok():
            calls.append("ok")
            return "ok"

        def boom():
            calls.append("boom")
            raise RuntimeError("worker fail")

        # First attempt uses pool; boom triggers sequential fallback which re-runs.
        # The helper returns sequential results after a worker exception — sequential
        # will raise again. Document current behavior: sequential re-raises.
        with self.assertRaises(RuntimeError):
            _run_online_probes_parallel([("a", ok), ("b", boom)])

    def test_empty_jobs(self):
        self.assertEqual(_run_online_probes_parallel([]), [])


class TestRunProbesParallelWiring(unittest.TestCase):
    @patch("claude_shield.probes.base._run_online_probes_parallel")
    @patch("claude_shield.probes.stability.check_egress_stability")
    @patch("claude_shield.probes.egress.check_dual_stack_egress")
    @patch("claude_shield.probes.cross_site.check_cross_site_routing")
    @patch("claude_shield.probes.reputation.check_ip_reputation")
    @patch("claude_shield.probes.dns_probe.check_dns_consistency")
    @patch("claude_shield.probes.egress.check_egress_consistency")
    @patch("claude_shield.probes.endpoints.get_all_endpoints")
    def test_online_uses_parallel_helper(
        self,
        mock_eps,
        mock_egress,
        mock_dns,
        mock_rep,
        mock_cross,
        mock_dual,
        mock_stab,
        mock_parallel,
    ):
        mock_eps.return_value = [
            {
                "id": "ipify-ipv4",
                "purpose": "public-egress-observation",
                "url": "https://api.ipify.org",
                "enabled": True,
                "supports_ipv4": True,
                "supports_ipv6": False,
                "expected_content_type": "text/plain",
                "maximum_response_bytes": 1024,
            }
        ]
        mock_egress.return_value = MagicMock(id="network.egress.runtime_consistency.ipify-ipv4")
        mock_parallel.return_value = [
            MagicMock(id="network.dns.consistency"),
            MagicMock(id="network.ip_reputation"),
            MagicMock(id="network.cross_site.routing"),
            MagicMock(id="network.egress.dual_stack"),
            MagicMock(id="network.egress.stability"),
        ]

        results = run_probes(online=True, timeout=3, intended_region="US")
        ids = [r.id for r in results]
        self.assertEqual(ids[0], "browser.webrtc.guidance")
        self.assertIn("network.egress.runtime_consistency.ipify-ipv4", ids)
        mock_parallel.assert_called_once()
        jobs = mock_parallel.call_args.args[0]
        self.assertEqual(
            [name for name, _fn in jobs],
            ["dns", "reputation", "cross_site", "dual_stack", "stability"],
        )
        # Extended probes are invoked via the parallel jobs, not directly beforehand.
        # Execute job callables to ensure kwargs wire correctly.
        for name, fn in jobs:
            fn()
        mock_dns.assert_called()
        self.assertTrue(mock_dns.call_args.kwargs.get("online"))
        mock_rep.assert_called()
        self.assertEqual(mock_rep.call_args.kwargs.get("intended_region"), "US")
        mock_cross.assert_called()
        mock_dual.assert_called()
        mock_stab.assert_called()

    @patch("claude_shield.probes.base._run_online_probes_parallel")
    def test_offline_does_not_parallelize(self, mock_parallel):
        results = run_probes(online=False)
        self.assertEqual([r.id for r in results], ["browser.webrtc.guidance"])
        mock_parallel.assert_not_called()

    @patch("claude_shield.probes.base._run_online_probes_parallel")
    @patch("claude_shield.probes.dns_probe.check_dns_consistency")
    @patch("claude_shield.probes.egress.check_egress_consistency")
    @patch("claude_shield.probes.safety.validate_url")
    def test_custom_endpoint_without_online_skips_parallel(
        self, mock_val, mock_egress, mock_dns, mock_parallel
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
        mock_parallel.assert_not_called()
        mock_dns.assert_called_once()
        self.assertFalse(mock_dns.call_args.kwargs.get("online"))


class TestParallelIntegrationMocked(unittest.TestCase):
    """End-to-end online path with real parallel helper, mocked probe bodies."""

    @patch("claude_shield.probes.stability.check_egress_stability")
    @patch("claude_shield.probes.egress.check_dual_stack_egress")
    @patch("claude_shield.probes.cross_site.check_cross_site_routing")
    @patch("claude_shield.probes.reputation.check_ip_reputation")
    @patch("claude_shield.probes.dns_probe.check_dns_consistency")
    @patch("claude_shield.probes.egress.check_egress_consistency")
    @patch("claude_shield.probes.endpoints.get_all_endpoints")
    def test_online_result_order(
        self, mock_eps, mock_egress, mock_dns, mock_rep, mock_cross, mock_dual, mock_stab
    ):
        mock_eps.return_value = [
            {
                "id": "ipify-ipv4",
                "purpose": "public-egress-observation",
                "url": "https://api.ipify.org",
                "enabled": True,
                "supports_ipv4": True,
                "supports_ipv6": False,
                "expected_content_type": "text/plain",
                "maximum_response_bytes": 1024,
            }
        ]
        mock_egress.return_value = MagicMock(id="network.egress.runtime_consistency.ipify-ipv4")

        def slow(name, delay):
            def _fn(*_a, **_k):
                time.sleep(delay)
                return MagicMock(id=name)

            return _fn

        mock_dns.side_effect = slow("network.dns.consistency", 0.04)
        mock_rep.side_effect = slow("network.ip_reputation", 0.03)
        mock_cross.side_effect = slow("network.cross_site.routing", 0.02)
        mock_dual.side_effect = slow("network.egress.dual_stack", 0.01)
        mock_stab.side_effect = slow("network.egress.stability", 0.005)

        results = run_probes(online=True, timeout=3, intended_region="JP")
        ids = [r.id for r in results]
        # webrtc, egress, then ordered independent probes
        self.assertEqual(
            ids,
            [
                "browser.webrtc.guidance",
                "network.egress.runtime_consistency.ipify-ipv4",
                "network.dns.consistency",
                "network.ip_reputation",
                "network.cross_site.routing",
                "network.egress.dual_stack",
                "network.egress.stability",
            ],
        )
        self.assertEqual(mock_rep.call_args.kwargs.get("intended_region"), "JP")


if __name__ == "__main__":
    unittest.main()
