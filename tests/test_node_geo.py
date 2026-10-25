"""Node display name geography vs observed egress country."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.analyze import analyze_snapshot
from claude_sonar.analysis.node_geo import named_region_codes, merge_node_geo_with_egress
from claude_sonar.models import AuditCheck, Evidence


def _ids(checks):
    return {c.id: c for c in checks}


class TestNamedRegionCodes(unittest.TestCase):
    def test_us_from_chinese_and_english(self):
        self.assertIn("US", named_region_codes("【3x】中转|美国Frontier家宽"))
        self.assertIn("US", named_region_codes("US-LosAngeles-01"))

    def test_japan_not_us(self):
        codes = named_region_codes("美国备用家宽三")
        self.assertIn("US", codes)
        self.assertNotIn("JP", codes)

    def test_tokyo_name(self):
        self.assertIn("JP", named_region_codes("【3x】中转|日本NTT家宽"))

    def test_no_region_token(self):
        self.assertEqual(named_region_codes("Node-01"), frozenset())


class TestNodeGeoCheck(unittest.TestCase):
    def _snap(self, node_name, egress_cc=None):
        data = {
            "Mihomo": {
                "AppConfigPresent": True,
                "PolicyGroups": {
                    "SelectionAssessment": "FixedSelection",
                    "RuntimeGroups": [{
                        "Name": "AI",
                        "SelectionChain": [
                            {"Name": "AI", "Type": "Selector", "Selected": node_name},
                            {"Name": node_name, "Type": "Vless", "Selected": ""},
                        ],
                    }],
                },
            }
        }
        if egress_cc:
            data["ObservedEgressCountry"] = egress_cc
        return data

    def test_match_pass(self):
        row = _ids(analyze_snapshot(self._snap("【3x】中转|美国Frontier家宽", "US")))["network.node_geo"]
        self.assertEqual(row.status, "pass")

    def test_mismatch_warning(self):
        row = _ids(analyze_snapshot(self._snap("美国备用家宽三", "JP")))["network.node_geo"]
        self.assertEqual(row.status, "warning")
        self.assertIn("JP", row.explanation)
        self.assertIn("US", row.explanation)

    def test_no_country_unknown(self):
        row = _ids(analyze_snapshot(self._snap("美国Frontier家宽")))["network.node_geo"]
        self.assertEqual(row.status, "unknown")

    def test_merge_from_reputation_evidence(self):
        checks = analyze_snapshot(self._snap("美国备用家宽三"))
        checks.append(AuditCheck(
            id="network.ip_reputation",
            title="t",
            category="network",
            status="pass",
            severity="info",
            confidence="confirmed",
            evidence=[Evidence(
                type="ip_reputation",
                description="x",
                data={"country_code": "JP"},
            )],
        ))
        merged = merge_node_geo_with_egress(checks)
        row = _ids(merged)["network.node_geo"]
        self.assertEqual(row.status, "warning")
        self.assertIn("JP", row.explanation)


if __name__ == "__main__":
    unittest.main()
