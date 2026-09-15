"""Standalone browser demo page: observation-only, zero third-party scripts."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

_DEMO = os.path.join(os.path.dirname(__file__), "..", "static", "demo.html")

# The demo may fetch from these hosts only (CORS-open, no API key). Observation
# of the browser's own egress; labeled third-party opinion. Nothing else may be
# contacted, and no third-party script may be embedded.
_ALLOWED_HOSTS = frozenset({"api.ipify.org", "ipwho.is"})


def _read():
    with open(_DEMO, encoding="utf-8") as f:
        return f.read()


class TestDemoPage(unittest.TestCase):
    def test_demo_page_exists(self):
        self.assertTrue(os.path.isfile(_DEMO), f"missing {_DEMO}")

    def test_no_third_party_assets(self):
        html = _read()
        self.assertNotRegex(html, r"<script[^>]+src=", "demo must not embed third-party scripts")
        self.assertNotRegex(html, r"<link[^>]+href=", "demo must not load external stylesheets")
        self.assertNotRegex(html, r"<img[^>]+src=['\"]https?://", "demo must not hotlink images")

    def test_web_rtc_observation_only(self):
        html = _read()
        self.assertIn("RTCPeerConnection", html)
        self.assertIn("host", html)  # candidate type observation
        self.assertIn("iceServers", html)

    def test_timezone_and_language_observation(self):
        html = _read()
        self.assertIn("resolvedOptions", html)
        self.assertIn("timeZone", html)
        self.assertIn("navigator.languages", html)

    def test_canvas_fingerprint_read_only(self):
        html = _read()
        self.assertIn("canvas", html.lower())
        self.assertIn("只读", html)  # read-only label

    def test_egress_fetch_allowlist(self):
        html = _read()
        script = html.split("<script>", 1)[1]
        hosts = set(re.findall(r"https?://([a-z0-9.\-]+)", script))
        foreign = hosts - _ALLOWED_HOSTS
        self.assertEqual(
            foreign, set(), f"demo contacts non-allowlisted hosts: {foreign}"
        )

    def test_boundary_text(self):
        html = _read()
        self.assertIn("只观测", html)
        self.assertIn("不伪装", html)
        self.assertIn("第三方", html)  # third-party label / opinion

    def test_links_to_full_tool(self):
        html = _read()
        self.assertIn("github.com/AschoofAlpha/claude-sonar", html)
        self.assertIn("pip install", html)

    def test_bilingual(self):
        html = _read()
        self.assertIn("时区", html)
        self.assertIn("timezone", html.lower())


if __name__ == "__main__":
    unittest.main()
