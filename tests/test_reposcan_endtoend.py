"""端到端测试：run_repo_scan 完整流程（栈检测 + 工具编排 stub + 评分 + baseline + SARIF）。"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_shield.reposcan import scanner as scanner_mod
from claude_shield.reposcan import tools as tools_mod
from claude_shield.reposcan.scanner import result_to_report, run_repo_scan
from claude_shield.reposcan.rules import rules_dir


def _fake_proc(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["fake"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _semgrep_findings_json(root, count_high=2, count_warn=1):
    results = []
    for i in range(count_high):
        results.append({
            "check_id": f"py-sql-injection-format-{i}",
            "path": str(root / "app.py"),
            "start": {"line": 10 + i, "col": 1},
            "extra": {"severity": "ERROR", "message": "SQL 查询使用字符串格式化拼接",
                      "metadata": {"cwe": ["CWE-89"]}},
        })
    for i in range(count_warn):
        results.append({
            "check_id": f"py-weak-crypto-{i}",
            "path": str(root / "util.py"),
            "start": {"line": 3 + i, "col": 1},
            "extra": {"severity": "WARNING", "message": "使用了弱加密算法"},
        })
    return json.dumps({"results": results, "errors": []})


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-e2e-")
        self.root = Path(self._tmp.name)
        (self.root / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
        (self.root / "app.py").write_text("print('x')\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_target_raises(self):
        with self.assertRaises(ValueError):
            run_repo_scan(self.root / "nope")
        with self.assertRaises(ValueError):
            run_repo_scan(self.root / "app.py")  # 是文件不是目录

    def test_all_tools_missing_graceful(self):
        with patch.object(tools_mod, "_which", return_value=None):
            result = run_repo_scan(self.root, json_out=True)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["schema_version"], "reposcan/1")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["distribution"],
                         {"critical": 0, "high": 0, "medium": 0, "low": 0})
        # 栈检测：Python + pip
        langs = [s["language"] for s in result["stack"]]
        self.assertIn("Python", langs)
        # 4 个工具全部 skipped
        self.assertEqual(len(result["tools"]), 4)
        for st in result["tools"]:
            self.assertEqual(st["status"], "skipped")
        # 报告渲染不炸且包含降级说明
        md = result_to_report(result)
        self.assertIn("代码仓库安全扫描报告", md)
        self.assertIn("已跳过", md)
        self.assertIn("semgrep --config", md)

    def test_semgrep_findings_scored_with_suggestions(self):
        def _fake_which(name):
            return "fake-semgrep" if name == "semgrep" else None

        def _fake_run(cmd, timeout, cwd=None):
            return _fake_proc(_semgrep_findings_json(self.root, count_high=2, count_warn=1),
                              returncode=1)

        with patch.object(tools_mod, "_which", side_effect=_fake_which), \
             patch.object(tools_mod, "_run", side_effect=_fake_run):
            result = run_repo_scan(self.root, json_out=True)

        self.assertEqual(result["score"], 100 - 15 * 2 - 6)  # 64
        self.assertEqual(result["grade"], "C")
        self.assertEqual(result["distribution"]["high"], 2)
        self.assertEqual(result["distribution"]["medium"], 1)
        self.assertEqual(len(result["findings"]), 3)
        # 高危发现附带修复建议
        high = [f for f in result["findings"] if f["severity"] == "high"]
        self.assertEqual(len(high), 2)
        for f in high:
            self.assertTrue(f["suggestion"])
            self.assertIn("参数化查询", f["suggestion"])
        # 指纹非空且去重
        fps = [f["fingerprint"] for f in result["findings"]]
        self.assertEqual(len(set(fps)), len(fps))
        # semgrep 状态 ok，其余 skipped
        st = {t["name"]: t for t in result["tools"]}
        self.assertEqual(st["semgrep"]["status"], "ok")
        self.assertEqual(st["gitleaks"]["status"], "skipped")

    def test_baseline_and_sarif_flow(self):
        baseline_path = self.root / ".." / "prev.json"
        # 上次扫描有 1 个已修复问题
        old = {
            "schema_version": "reposcan/1",
            "score": 85,
            "findings": [{
                "tool": "semgrep", "rule_id": "old-rule", "severity": "high",
                "path": "old.py", "line": 1, "message": "old problem",
                "fingerprint": "deadbeef00000000",
            }],
        }
        baseline_path.write_text(json.dumps(old), encoding="utf-8")
        sarif_path = self.root / ".." / "scan.sarif"

        def _fake_which(name):
            return "fake-semgrep" if name == "semgrep" else None

        def _fake_run(cmd, timeout, cwd=None):
            return _fake_proc(_semgrep_findings_json(self.root, count_high=1, count_warn=0),
                              returncode=1)

        with patch.object(tools_mod, "_which", side_effect=_fake_which), \
             patch.object(tools_mod, "_run", side_effect=_fake_run):
            result = run_repo_scan(self.root, json_out=True,
                                   baseline_path=baseline_path,
                                   sarif_path=sarif_path)

        self.assertEqual(result["score"], 85)  # 100 - 15
        b = result["baseline"]
        self.assertEqual(b["added"], 1)
        self.assertEqual(b["fixed"], 1)
        self.assertEqual(b["worsened"], 0)
        self.assertEqual(b["score_delta"], 0)
        self.assertEqual(b["previous_score"], 85)
        # SARIF 文件已写出且结构合法
        self.assertTrue(result["sarif"]["written"])
        self.assertTrue(sarif_path.is_file())
        doc = json.loads(sarif_path.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)
        # 报告含 baseline 段落
        md = result_to_report(result)
        self.assertIn("与上次扫描对比", md)

    def test_use_tools_false_stack_only(self):
        result = run_repo_scan(self.root, use_tools=False, json_out=True)
        self.assertEqual(result["tools"], [])
        self.assertEqual(result["score"], 100)
        self.assertIn("Python", [s["language"] for s in result["stack"]])
        self.assertTrue(any("未启用" in n for n in result["notes"]))

    def test_json_out_false_returns_object(self):
        with patch.object(tools_mod, "_which", return_value=None):
            result = run_repo_scan(self.root, json_out=False)
        self.assertTrue(hasattr(result, "to_dict"))
        d = result.to_dict()
        self.assertEqual(d["score"], 100)

    def test_rules_dir_packaged(self):
        d = rules_dir()
        self.assertTrue(d.is_dir(), str(d))
        yamls = sorted(p.name for p in d.glob("*.yaml"))
        self.assertEqual(
            yamls,
            ["csharp.yaml", "go.yaml", "java.yaml", "javascript.yaml",
             "php.yaml", "python.yaml", "ruby.yaml", "rust.yaml"],
        )
        self.assertTrue((d / "NOTICE.md").is_file())

    def test_semgrep_configs_follow_stack_languages(self):
        captured = {}
        def _fake_which(name):
            return "fake-semgrep" if name == "semgrep" else None
        def _capture(cmd, timeout, cwd=None):
            captured["cmd"] = list(cmd)
            return _fake_proc("{}")
        with patch.object(tools_mod, "_which", side_effect=_fake_which), \
             patch.object(tools_mod, "_run", side_effect=_capture):
            run_repo_scan(self.root, json_out=True)
        configs = [captured["cmd"][i + 1] for i, a in enumerate(captured["cmd"])
                   if a == "--config"]
        # Python 栈 -> 只选 python.yaml
        self.assertEqual(configs, [str(rules_dir() / "python.yaml")])


if __name__ == "__main__":
    unittest.main()
