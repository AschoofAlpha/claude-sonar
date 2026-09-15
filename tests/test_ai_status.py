"""AI-platform connectivity observation (online only, reachability only).

Fetches a fixed list of AI platform homepages through the same proxy-aware
HTTP path as the other online probes and records per-platform reachability.
No credentials, no IP extraction, no verdict — a failed platform is reported
as unknown, never as a leak or an account-risk claim.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from claude_sonar.probes import ai_status
from claude_sonar.report import classify_action


def _fake_fetch(ok_urls, fail_urls):
    def fake(url, timeout=5, max_bytes=16384):
        if url in fail_urls:
            raise ai_status.ProbeError("simulated failure")
        assert url in ok_urls, f"unexpected url {url}"
        return "<html></html>", "proxy_limited"
    return fake


class TestAiConnectivity(unittest.TestCase):
    def test_default_targets_are_https_homepages(self):
        for platform, url in ai_status.DEFAULT_AI_PLATFORM_URLS:
            self.assertTrue(url.startswith("https://"), url)
            self.assertTrue(platform)

    def test_all_reachable_is_pass(self):
        urls = [u for _, u in ai_status.DEFAULT_AI_PLATFORM_URLS]
        ai_status.fetch_http = _fake_fetch(ok_urls=urls, fail_urls=[])
        try:
            check = ai_status.check_ai_connectivity(timeout=2)
        finally:
            ai_status.fetch_http = ai_status._original_fetch_http
        self.assertEqual(check.id, "network.ai_connectivity")
        self.assertEqual(check.status, "pass")
        self.assertEqual(classify_action(check), "leave_alone")

    def test_any_failure_is_unknown_with_failure_list(self):
        urls = [u for _, u in ai_status.DEFAULT_AI_PLATFORM_URLS]
        fail = urls[-1]
        ai_status.fetch_http = _fake_fetch(ok_urls=[u for u in urls if u != fail], fail_urls=[fail])
        try:
            check = ai_status.check_ai_connectivity(timeout=2)
        finally:
            ai_status.fetch_http = ai_status._original_fetch_http
        self.assertEqual(check.status, "unknown")
        self.assertEqual(classify_action(check), "leave_alone")
        data = check.evidence[0].data
        failed = [p for p in data["platforms"] if not p.get("reachable")]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["error"], "ProbeError")

    def test_custom_urls_override(self):
        custom = [("Custom", "https://example.com/")]
        ai_status.fetch_http = _fake_fetch(ok_urls=["https://example.com/"], fail_urls=[])
        try:
            check = ai_status.check_ai_connectivity(timeout=2, urls=custom)
        finally:
            ai_status.fetch_http = ai_status._original_fetch_http
        self.assertEqual(check.status, "pass")
        self.assertEqual(check.evidence[0].data["platforms"][0]["platform"], "Custom")

    def test_all_failed_is_unknown_not_fail(self):
        urls = [u for _, u in ai_status.DEFAULT_AI_PLATFORM_URLS]
        ai_status.fetch_http = _fake_fetch(ok_urls=[], fail_urls=urls)
        try:
            check = ai_status.check_ai_connectivity(timeout=2)
        finally:
            ai_status.fetch_http = ai_status._original_fetch_http
        self.assertEqual(check.status, "unknown")
        self.assertNotEqual(check.status, "fail")


if __name__ == "__main__":
    unittest.main()
