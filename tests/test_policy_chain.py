"""Policy selection chain must pin to a concrete leaf node."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot
from claude_sonar.analysis.policy_chain import (
    assess_policy_chain,
    format_selection_chain,
    leaf_of_chain,
)


def _ids(checks):
    return {c.id: c for c in checks}


def _snapshot(chain, assessment="FixedSelection"):
    return {
        "Mihomo": {
            "AppConfigPresent": True,
            "PolicyGroups": {
                "SelectionAssessment": assessment,
                "RuntimeGroups": [{
                    "Name": "AI",
                    "ReferencedByRule": True,
                    "UsesAutomaticSelection": False,
                    "SelectionChain": chain,
                }],
            },
        }
    }


class TestPolicyChainHelpers(unittest.TestCase):
    def test_format_chain(self):
        chain = [
            {"Name": "AI服务", "Type": "Selector", "Selected": "苏菲家宽"},
            {"Name": "苏菲家宽", "Type": "Selector", "Selected": "自动选择"},
            {"Name": "自动选择", "Type": "URLTest", "Selected": "x"},
        ]
        self.assertEqual(
            format_selection_chain(chain),
            "AI服务 → 苏菲家宽 → 自动选择",
        )

    def test_leaf_is_last_link(self):
        chain = [
            {"Name": "AI", "Type": "Selector", "Selected": "Node1"},
            {"Name": "Node1", "Type": "Vless", "Selected": ""},
        ]
        leaf = leaf_of_chain(chain)
        self.assertEqual(leaf["Name"], "Node1")
        self.assertEqual(leaf["Type"], "Vless")


class TestPolicyChainCheck(unittest.TestCase):
    def test_concrete_leaf_pass_includes_chain(self):
        checks = analyze_snapshot(_snapshot([
            {"Name": "AI服务", "Type": "Selector", "Selected": "苏菲家宽"},
            {"Name": "苏菲家宽", "Type": "Selector", "Selected": "Frontier"},
            {"Name": "Frontier", "Type": "Vless", "Selected": ""},
        ]))
        row = _ids(checks)["network.policy_chain"]
        self.assertEqual(row.status, "pass")
        self.assertIn("AI服务 → 苏菲家宽 → Frontier", row.explanation)

    def test_urltest_leaf_warning(self):
        checks = analyze_snapshot(_snapshot([
            {"Name": "AI服务", "Type": "Selector", "Selected": "苏菲家宽"},
            {"Name": "苏菲家宽", "Type": "Selector", "Selected": "自动选择"},
            {"Name": "自动选择", "Type": "URLTest", "Selected": "node"},
        ]))
        row = _ids(checks)["network.policy_chain"]
        self.assertEqual(row.status, "warning")
        self.assertIn("URLTest", row.explanation)
        self.assertIn("AI服务 → 苏菲家宽 → 自动选择", row.explanation)

    def test_fallback_leaf_warning(self):
        status, explanation = assess_policy_chain([{
            "SelectionChain": [
                {"Name": "AI", "Type": "Selector", "Selected": "故障转移"},
                {"Name": "故障转移", "Type": "Fallback", "Selected": "n"},
            ]
        }])
        self.assertEqual(status, "warning")
        self.assertIn("Fallback", explanation)

    def test_empty_chain_unknown(self):
        checks = analyze_snapshot(_snapshot([]))
        row = _ids(checks)["network.policy_chain"]
        self.assertEqual(row.status, "unknown")


if __name__ == "__main__":
    unittest.main()
