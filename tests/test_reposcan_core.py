"""评分 / baseline 对比 / SARIF / 建议生成 的单元测试。"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_shield.reposcan.baseline import diff_baseline, load_baseline
from claude_shield.reposcan.models import Finding
from claude_shield.reposcan.sarif import findings_to_sarif, write_sarif
from claude_shield.reposcan.scoring import compute_score, grade_of, severity_distribution
from claude_shield.reposcan.suggest import suggestion_for


def _f(tool="semgrep", rule_id="r", severity="medium", path="a.py", line=1,
       message="m"):
    f = Finding(tool=tool, rule_id=rule_id, severity=severity, path=path,
                line=line, message=message)
    f.compute_fingerprint()
    return f


class TestScoring(unittest.TestCase):
    def test_clean_score_100(self):
        s = compute_score([])
        self.assertEqual(s["score"], 100)
        self.assertEqual(s["grade"], "A")
        self.assertEqual(s["distribution"], {"critical": 0, "high": 0, "medium": 0, "low": 0})

    def test_weighted_penalty(self):
        findings = [
            _f(severity="critical"), _f(severity="critical"),
            _f(severity="high"), _f(severity="high"), _f(severity="high"),
            _f(severity="medium"), _f(severity="low"),
        ]
        s = compute_score(findings)
        # 25*2 + 15*3 + 6 + 2 = 103 -> 下限 0
        self.assertEqual(s["score"], 0)
        self.assertEqual(s["grade"], "F")
        self.assertEqual(s["distribution"]["critical"], 2)
        self.assertEqual(s["distribution"]["high"], 3)

    def test_partial_penalty(self):
        findings = [_f(severity="high"), _f(severity="high"), _f(severity="medium")]
        s = compute_score(findings)
        self.assertEqual(s["score"], 100 - 30 - 6)
        self.assertEqual(s["grade"], "C")  # 64

    def test_unknown_severity_counts_as_low(self):
        s = compute_score([_f(severity="weird")])
        self.assertEqual(s["distribution"]["low"], 1)
        self.assertEqual(s["score"], 98)

    def test_grade_boundaries(self):
        self.assertEqual(grade_of(90)[0], "A")
        self.assertEqual(grade_of(75)[0], "B")
        self.assertEqual(grade_of(60)[0], "C")
        self.assertEqual(grade_of(40)[0], "D")
        self.assertEqual(grade_of(39)[0], "F")

    def test_distribution_standalone(self):
        dist = severity_distribution([_f(severity="critical"), _f(severity="HIGH"), _f(severity="MODERATE")])
        self.assertEqual(dist, {"critical": 1, "high": 1, "medium": 1, "low": 0})


class TestBaseline(unittest.TestCase):
    def _old(self, findings):
        return {"score": 70, "findings": [f.to_dict() for f in findings]}

    def test_added_fixed_worsened(self):
        old = self._old([
            _f(rule_id="old-fixed", severity="high"),
            _f(rule_id="worse-me", severity="medium"),
            _f(rule_id="stable", severity="high"),
        ])
        new = [
            _f(rule_id="worse-me", severity="high"),   # 恶化
            _f(rule_id="stable", severity="high"),     # 不变
            _f(rule_id="new-added", severity="low"),   # 新增
        ]
        diff = diff_baseline(new, old, new_score=80)
        self.assertEqual(diff["added"], 1)
        self.assertEqual(diff["fixed"], 1)
        self.assertEqual(diff["worsened"], 1)
        self.assertEqual(diff["score_delta"], 10)
        self.assertEqual(diff["previous_score"], 70)
        added_ids = [f["rule_id"] for f in diff["added_findings"]]
        self.assertEqual(added_ids, ["new-added"])

    def test_missing_file_returns_error(self):
        data, err = load_baseline("C:/definitely/not/exists.json")
        self.assertIsNone(data)
        self.assertIn("不存在", err)

    def test_malformed_json_returns_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{not json", encoding="utf-8")
            data, err = load_baseline(p)
        self.assertIsNone(data)
        self.assertIn("JSON", err)

    def test_valid_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "base.json"
            p.write_text(json.dumps({"score": 88, "findings": []}), encoding="utf-8")
            data, err = load_baseline(p)
        self.assertIsNone(err)
        self.assertEqual(data["score"], 88)


class TestSarif(unittest.TestCase):
    def _result(self):
        f = _f(rule_id="py-sql-injection-format", severity="high", line=42, message="SQL 拼接")
        f.cwe = "CWE-89"
        return {"findings": [f.to_dict()], "score": 85}

    def test_structure_valid_210(self):
        doc = findings_to_sarif(self._result(), tool_version="1.4.2")
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "claude-shield-reposcan")
        self.assertEqual(run["tool"]["driver"]["semanticVersion"], "1.4.2")
        self.assertEqual(len(run["results"]), 1)
        r = run["results"][0]
        self.assertEqual(r["ruleId"], "py-sql-injection-format")
        self.assertEqual(r["level"], "error")  # high -> error
        loc = r["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "a.py")
        self.assertEqual(loc["region"]["startLine"], 42)
        # 规则索引引用有效
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"][r["ruleIndex"]]["id"], r["ruleId"])

    def test_level_mapping(self):
        cases = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        for sev, lvl in cases.items():
            f = _f(severity=sev)
            doc = findings_to_sarif({"findings": [f.to_dict()]})
            self.assertEqual(doc["runs"][0]["results"][0]["level"], lvl, msg=sev)

    def test_line_zero_omits_region(self):
        f = _f(line=0)
        doc = findings_to_sarif({"findings": [f.to_dict()]})
        loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertNotIn("region", loc)

    def test_write_sarif_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sub" / "report.sarif"
            written = write_sarif(p, findings_to_sarif(self._result()))
            data = json.loads(written.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "2.1.0")

    def test_rules_deduplicated(self):
        f1 = _f(rule_id="r1", severity="high")
        f2 = _f(rule_id="r1", severity="high", line=2)
        doc = findings_to_sarif({"findings": [f1.to_dict(), f2.to_dict()]})
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(len(doc["runs"][0]["results"]), 2)


class TestSuggestions(unittest.TestCase):
    def test_sql_injection_advice(self):
        s = suggestion_for({"tool": "semgrep", "rule_id": "py-sql-injection-format"})
        self.assertIn("参数化查询", s)

    def test_command_injection_advice(self):
        s = suggestion_for({"tool": "semgrep", "rule_id": "py-command-injection-subprocess-shell"})
        self.assertIn("shell=False", s)

    def test_gitleaks_advice(self):
        s = suggestion_for({"tool": "gitleaks", "rule_id": "gitleaks:generic-api-key"})
        self.assertIn("轮换", s)

    def test_fallback_advice(self):
        s = suggestion_for({"tool": "semgrep", "rule_id": "some-unknown-rule"})
        self.assertIn("人工确认", s)


if __name__ == "__main__":
    unittest.main()
