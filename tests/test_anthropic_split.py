"""Anthropic properties must share one egress token."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.probes.anthropic_split import check_anthropic_split
from claude_sonar.report import classify_action


class TestAnthropicSplit(unittest.TestCase):
    def test_same_token_pass(self):
        row = check_anthropic_split(observations=[
            {"site": "claude.ai", "observed_address": "tok-aaa"},
            {"site": "claude.com", "observed_address": "tok-aaa"},
            {"site": "www.anthropic.com", "observed_address": "tok-aaa"},
        ])
        self.assertEqual(row.id, "network.anthropic_split")
        self.assertEqual(row.status, "pass")

    def test_mismatch_fail_is_must_fix(self):
        row = check_anthropic_split(observations=[
            {"site": "claude.ai", "observed_address": "tok-aaa"},
            {"site": "claude.com", "observed_address": "tok-bbb"},
            {"site": "www.anthropic.com", "observed_address": "tok-aaa"},
        ])
        self.assertEqual(row.status, "fail")
        self.assertEqual(classify_action(row), "must_fix")
        self.assertIn("claude.com", row.explanation)

    def test_insufficient_unknown(self):
        row = check_anthropic_split(observations=[
            {"site": "claude.ai", "observed_address": "tok-aaa"},
        ])
        self.assertEqual(row.status, "unknown")


if __name__ == "__main__":
    unittest.main()
