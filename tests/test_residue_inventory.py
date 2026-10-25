"""Local Claude residue inventory: A cache / B identity / C sessions / D assets."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot
from claude_sonar.analysis.residue import classify_label, summarize_inventory
from claude_sonar.report import classify_action


def _ids(checks):
    return {c.id: c for c in checks}


class TestResidueClassify(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(classify_label("claude_cache_dir"), "A")
        self.assertEqual(classify_label("claude_statsig_dir"), "A")
        self.assertEqual(classify_label("claude_json"), "B")
        self.assertEqual(classify_label("claude_credentials"), "B")
        self.assertEqual(classify_label("claude_projects"), "C")
        self.assertEqual(classify_label("claude_file_history"), "C")
        self.assertEqual(classify_label("claude_skills"), "D")
        self.assertEqual(classify_label("claude_settings_json"), "D")

    def test_summarize_bytes_by_category(self):
        summary = summarize_inventory([
            {"Label": "claude_cache_dir", "Present": True, "SizeBytes": 10_000_000},
            {"Label": "claude_json", "Present": True, "SizeBytes": 400},
            {"Label": "claude_projects", "Present": True, "SizeBytes": 3_600_000_000},
            {"Label": "claude_skills", "Present": True, "SizeBytes": 36_000_000},
            {"Label": "missing_thing", "Present": False, "SizeBytes": 1},
        ])
        self.assertEqual(summary["A"]["bytes"], 10_000_000)
        self.assertEqual(summary["B"]["bytes"], 400)
        self.assertEqual(summary["C"]["bytes"], 3_600_000_000)
        self.assertEqual(summary["D"]["bytes"], 36_000_000)
        self.assertEqual(summary["A"]["count"], 1)


class TestResidueCheck(unittest.TestCase):
    def test_empty_pass(self):
        row = _ids(analyze_snapshot({"ClaudeCode": {"LocalArtifacts": []}}))["privacy.residue_inventory"]
        self.assertEqual(row.status, "pass")
        self.assertEqual(classify_action(row), "leave_alone")

    def test_inventory_lists_categories(self):
        row = _ids(analyze_snapshot({
            "ClaudeCode": {
                "LocalArtifacts": [
                    {"Label": "claude_projects", "Present": True, "SizeBytes": 1000},
                    {"Label": "claude_json", "Present": True, "SizeBytes": 50},
                ]
            }
        }))["privacy.residue_inventory"]
        self.assertEqual(row.status, "unknown")
        self.assertIn("B", row.explanation)
        self.assertIn("C", row.explanation)
        self.assertEqual(classify_action(row), "leave_alone")

    def test_assets_only_pass(self):
        row = _ids(analyze_snapshot({
            "ClaudeCode": {
                "LocalArtifacts": [
                    {"Label": "claude_skills", "Present": True, "SizeBytes": 100},
                ]
            }
        }))["privacy.residue_inventory"]
        self.assertEqual(row.status, "pass")


if __name__ == "__main__":
    unittest.main()
