import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_shield.analyze import analyze_snapshot


class TestPrivacyArtifacts(unittest.TestCase):
    def test_recommends_when_artifacts_present(self):
        checks = analyze_snapshot(
            {
                "ClaudeCode": {
                    "DeviceIdArtifactPresent": True,
                    "TelemetryCachePresent": True,
                    "LocalArtifacts": [
                        {"Label": "claude_home_dir", "Present": True, "Kind": "directory", "SizeBytes": 100},
                        {"Label": "claude_statsig_dir", "Present": True, "Kind": "directory", "SizeBytes": 50},
                    ],
                },
                "Browsers": {
                    "Chrome": {"Installed": True, "RestrictiveWebRtcPolicyDetected": False},
                },
                "System": {},
                "Mihomo": {},
            },
            include_recommendations=True,
        )
        by_id = {c.id: c for c in checks}
        self.assertIn("privacy.local_device_id", by_id)
        self.assertIn("privacy.telemetry_cache", by_id)
        self.assertIn("privacy.browser_fingerprint", by_id)
        self.assertEqual(by_id["privacy.local_device_id"].status, "unknown")
        rec = (by_id["privacy.local_device_id"].recommendation or "").lower()
        self.assertIn("cannot clear", rec)
        self.assertIn("server-side", rec)
        self.assertIn("anti-detect", (by_id["privacy.browser_fingerprint"].recommendation or "").lower())

    def test_pass_when_absent(self):
        checks = analyze_snapshot(
            {
                "ClaudeCode": {
                    "DeviceIdArtifactPresent": False,
                    "TelemetryCachePresent": False,
                    "LocalArtifacts": [],
                },
                "Browsers": {
                    "Chrome": {"Installed": True, "RestrictiveWebRtcPolicyDetected": True},
                },
            },
            include_recommendations=True,
        )
        by_id = {c.id: c for c in checks}
        self.assertEqual(by_id["privacy.local_device_id"].status, "pass")
        self.assertEqual(by_id["privacy.telemetry_cache"].status, "pass")
        self.assertEqual(by_id["privacy.browser_fingerprint"].status, "pass")


if __name__ == "__main__":
    unittest.main()
