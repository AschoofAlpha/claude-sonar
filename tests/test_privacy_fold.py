"""Supplemental privacy fold: not_configured OTEL/prompt_history/scrub leave_alone."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot
from claude_sonar.report import classify_action, score_checks


def _ids(checks):
    return {c.id: c for c in checks}


_SUPPLEMENTAL = (
    "privacy.prompt_history",
    "privacy.subprocess_scrub",
    "privacy.otel_user_prompts",
    "privacy.otel_tool_content",
    "privacy.otel_tool_details",
    "privacy.otel_raw_api",
)


class TestPrivacyFold(unittest.TestCase):
    def test_supplemental_folded_when_absent(self):
        checks = analyze_snapshot({"ClaudeCode": {}}, include_recommendations=True)
        ids = _ids(checks)
        for cid in _SUPPLEMENTAL:
            self.assertIn(cid, ids)
            expl = ids[cid].explanation
            self.assertIn("[folded_optional]", expl)
            self.assertIn("补充项未配置", expl)
            self.assertEqual(ids[cid].recommendation or "", "")
            self.assertEqual(classify_action(ids[cid]), "leave_alone")

    def test_core_privacy_still_not_configured(self):
        checks = analyze_snapshot({"ClaudeCode": {}})
        ids = _ids(checks)
        self.assertIn("[not_configured]", ids["privacy.telemetry"].explanation)
        self.assertEqual(classify_action(ids["privacy.telemetry"]), "optional_consistency")

    def test_folded_does_not_inflate_optional_score(self):
        # Only folded supplemental unknowns should not drag optional_penalty hard
        checks = analyze_snapshot({"ClaudeCode": {}})
        scored = score_checks(checks)
        # leave_alone count should include the 6 supplemental folded items
        leave = scored["breakdown"]["leave_alone"]
        self.assertGreaterEqual(leave, 6)
        # optional_consistency still has core privacy.telemetry/errors/nonessential
        self.assertGreaterEqual(scored["breakdown"]["optional_consistency"], 3)

    def test_active_supplemental_is_pass(self):
        checks = analyze_snapshot(
            {
                "ClaudeCode": {
                    "SkipPromptHistoryActive": True,
                    "SkipPromptHistoryVars": [
                        {"Scope": "Process", "Present": True, "Active": True, "Value": "1"},
                    ],
                }
            }
        )
        ph = _ids(checks)["privacy.prompt_history"]
        self.assertEqual(ph.status, "pass")
        self.assertNotIn("[folded_optional]", ph.explanation)


if __name__ == "__main__":
    unittest.main()
