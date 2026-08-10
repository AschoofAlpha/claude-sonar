import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestProbesSmoke(unittest.TestCase):
    """Smoke tests for the retained probes package (live network checks)."""

    def test_probes_importable(self):
        from claude_shield.probes.base import run_probes
        self.assertTrue(callable(run_probes))

    def test_probes_offline_run_returns_empty(self):
        # Default offline path must not contact the network.
        from claude_shield.probes.base import run_probes
        results = run_probes(None, timeout=3, online=False)
        self.assertEqual(results, [])

    def test_probes_accepts_online_kwarg(self):
        from claude_shield.probes.base import run_probes
        import inspect
        self.assertIn("online", inspect.signature(run_probes).parameters)

    def test_endpoints_known(self):
        from claude_shield.probes import endpoints
        eps = endpoints.get_all_endpoints()
        self.assertIsInstance(eps, list)
        self.assertTrue(any(e.get("id") == "cloudflare-trace" for e in eps))


if __name__ == "__main__":
    unittest.main()
