"""外部工具编排测试：缺失降级、超时保护、各工具输出解析（stub subprocess）。"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.reposcan import tools as tools_mod
from claude_sonar.reposcan.tools import ToolRunner


def _fake_proc(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["fake"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class TestToolMissingGraceful(unittest.TestCase):
    """工具全部未安装：跳过 + 安装提示，绝不抛异常。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-tools-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_all_missing_all_skipped_with_hints(self):
        with patch.object(tools_mod, "_which", return_value=None):
            runner = ToolRunner(self.root)
            findings, statuses, notes = runner.run_all({"Python", "JavaScript/TypeScript"})
        self.assertEqual(findings, [])
        self.assertEqual(len(statuses), 6)
        for st in statuses:
            self.assertEqual(st.status, "skipped", msg=st.name)
            self.assertFalse(st.available)
            self.assertTrue(st.install_hint, msg=st.name)
        # semgrep 跳过时必须给出手动运行提示
        self.assertTrue(any("semgrep --config" in n for n in notes), notes)

    def test_semgrep_missing_returns_manual_hint(self):
        with patch.object(tools_mod, "_which", return_value=None):
            runner = ToolRunner(self.root)
            findings, st = runner.run_semgrep([Path("x.yaml")], target_display="demo")
        self.assertEqual(st.status, "skipped")
        self.assertIn("pip install semgrep", st.install_hint)
        self.assertIn("semgrep --config", st.install_hint)


class TestSemgrepParse(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-semgrep-")
        self.root = Path(self._tmp.name)
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _semgrep_json(self):
        return json.dumps({
            "results": [
                {"check_id": "py-sql-injection-format",
                 "path": str(self.root / "app.py"),
                 "start": {"line": 42, "col": 1},
                 "extra": {"severity": "ERROR",
                           "message": "SQL 查询使用字符串格式化拼接",
                           "metadata": {"cwe": ["CWE-89"]}}},
                {"check_id": "py-weak-crypto",
                 "path": str(self.root / "util.py"),
                 "start": {"line": 7, "col": 1},
                 "extra": {"severity": "WARNING",
                           "message": "使用了弱加密算法"}},
                {"check_id": "py-note-rule",
                 "path": str(self.root / "x.py"),
                 "start": {"line": 1, "col": 1},
                 "extra": {"severity": "INFO", "message": "提示"}},
            ],
            "errors": [],
        })

    def test_parse_results_and_severity_mapping(self):
        with patch.object(tools_mod, "_which", return_value="semgrep"), \
             patch.object(tools_mod, "_run", return_value=_fake_proc(self._semgrep_json(), returncode=1)):
            runner = ToolRunner(self.root)
            findings, st = runner.run_semgrep([Path("r.yaml")])
        self.assertEqual(st.status, "ok")
        self.assertEqual(len(findings), 3)
        by_id = {f.rule_id: f for f in findings}
        self.assertEqual(by_id["py-sql-injection-format"].severity, "high")
        self.assertEqual(by_id["py-sql-injection-format"].cwe, "CWE-89")
        self.assertEqual(by_id["py-weak-crypto"].severity, "medium")
        self.assertEqual(by_id["py-note-rule"].severity, "low")
        self.assertEqual(by_id["py-sql-injection-format"].line, 42)
        # 路径相对化 + 正斜杠
        self.assertEqual(by_id["py-sql-injection-format"].path, "app.py")

    def test_unparseable_output_is_error_not_crash(self):
        with patch.object(tools_mod, "_which", return_value="semgrep"), \
             patch.object(tools_mod, "_run", return_value=_fake_proc("semgrep: not found", stderr="boom", returncode=2)):
            runner = ToolRunner(self.root)
            findings, st = runner.run_semgrep([Path("r.yaml")])
        self.assertEqual(findings, [])
        self.assertEqual(st.status, "error")
        self.assertIn("无法解析", st.detail)

    def test_timeout_is_error_status(self):
        def _timeout(cmd, timeout, cwd=None):
            raise subprocess.TimeoutExpired(cmd, timeout)
        with patch.object(tools_mod, "_which", return_value="semgrep"), \
             patch.object(tools_mod, "_run", side_effect=_timeout):
            runner = ToolRunner(self.root)
            findings, st = runner.run_semgrep([Path("r.yaml")])
        self.assertEqual(findings, [])
        self.assertEqual(st.status, "error")
        self.assertIn("超时", st.detail)

    def test_cmd_uses_shell_false_list_args(self):
        captured = {}
        def _capture(cmd, timeout, cwd=None):
            captured["cmd"] = list(cmd)
            captured["timeout"] = timeout
            return _fake_proc("{}")
        with patch.object(tools_mod, "_which", return_value=r"C:\Tools\semgrep.exe"), \
             patch.object(tools_mod, "_run", side_effect=_capture):
            runner = ToolRunner(self.root)
            runner.run_semgrep([Path("r.yaml")])
        cmd = captured["cmd"]
        self.assertEqual(cmd[0], r"C:\Tools\semgrep.exe")
        self.assertIn("--json", cmd)
        self.assertIn("--config", cmd)
        self.assertEqual(cmd[-1], str(self.root.resolve()))
        self.assertEqual(captured["timeout"], tools_mod._DEFAULT_TIMEOUTS["semgrep"])


class TestGitleaksParse(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-gitleaks-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_gitleaks_run(self, cmd, timeout, cwd=None):
        # 把报告写进 --report-path 指定的文件，返回退出码 1（有发现）
        report = cmd[cmd.index("--report-path") + 1]
        data = [{
            "RuleID": "generic-api-key",
            "File": str(self.root / "config.py"),
            "StartLine": 9,
            "Secret": "sk-abcdefghijklmnopqrstuvwxyz123456",
            "Entropy": 4.2,
        }]
        with open(report, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return _fake_proc("", returncode=1)

    def test_parse_report_and_cleanup(self):
        with patch.object(tools_mod, "_which", return_value="gitleaks"), \
             patch.object(tools_mod, "_run", side_effect=self._fake_gitleaks_run):
            runner = ToolRunner(self.root)
            findings, st = runner.run_gitleaks()
        self.assertEqual(st.status, "ok")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.cwe, "CWE-798")
        self.assertEqual(f.path, "config.py")
        self.assertEqual(f.line, 9)
        # 密钥被截断，不完整出现在报告里
        self.assertNotIn("qrstuvwxyz", f.message)
        self.assertIn("sk-abcdefg", f.message)

    def test_no_git_uses_no_git_flag(self):
        captured = {}
        def _capture(cmd, timeout, cwd=None):
            captured["cmd"] = list(cmd)
            report = cmd[cmd.index("--report-path") + 1]
            with open(report, "w", encoding="utf-8") as fh:
                json.dump([], fh)
            return _fake_proc("", returncode=0)
        with patch.object(tools_mod, "_which", return_value="gitleaks"), \
             patch.object(tools_mod, "_run", side_effect=_capture):
            runner = ToolRunner(self.root)
            findings, st = runner.run_gitleaks()
        self.assertIn("--no-git", captured["cmd"])
        self.assertEqual(st.status, "ok")
        self.assertEqual(findings, [])


class TestPipAuditParse(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-pipaudit-")
        self.root = Path(self._tmp.name)
        (self.root / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_parse_vulns_with_severity(self):
        payload = json.dumps([{
            "name": "requests", "version": "2.25.0",
            "vulns": [
                {"id": "GHSA-xxxx", "severity": "HIGH",
                 "description": "CRLF injection", "fix_versions": ["2.31.0"]},
                {"id": "GHSA-yyyy",
                 "description": "cert verification issue"},
            ],
        }])
        with patch.object(tools_mod, "_which", return_value="pip-audit"), \
             patch.object(tools_mod, "_run", return_value=_fake_proc(payload, returncode=1)):
            runner = ToolRunner(self.root)
            findings, st = runner.run_pip_audit(python_detected=True)
        self.assertEqual(st.status, "ok")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[1].severity, "medium")  # 缺省 severity
        self.assertIn("2.31.0", findings[0].message)
        self.assertEqual(findings[0].path, "requirements.txt")

    def test_skipped_when_not_python(self):
        with patch.object(tools_mod, "_which", return_value="pip-audit"):
            runner = ToolRunner(self.root)
            findings, st = runner.run_pip_audit(python_detected=False)
        self.assertEqual(st.status, "skipped")
        self.assertEqual(findings, [])

    def test_skipped_without_manifest(self):
        (self.root / "requirements.txt").unlink()
        with patch.object(tools_mod, "_which", return_value="pip-audit"):
            runner = ToolRunner(self.root)
            findings, st = runner.run_pip_audit(python_detected=True)
        self.assertEqual(st.status, "skipped")
        self.assertIn("依赖清单", st.detail)

    def test_uses_requirements_flag(self):
        captured = {}
        def _capture(cmd, timeout, cwd=None):
            captured["cmd"] = list(cmd)
            return _fake_proc("[]")
        with patch.object(tools_mod, "_which", return_value="pip-audit"), \
             patch.object(tools_mod, "_run", side_effect=_capture):
            runner = ToolRunner(self.root)
            runner.run_pip_audit(python_detected=True)
        self.assertIn("-r", captured["cmd"])
        self.assertIn("--format", captured["cmd"])
        self.assertIn("json", captured["cmd"])


class TestNpmAuditParse(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-npm-")
        self.root = Path(self._tmp.name)
        (self.root / "package-lock.json").write_text("{}", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_parse_vulnerabilities(self):
        payload = json.dumps({
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "via": [{"title": "Prototype Pollution", "name": "lodash"}],
                },
                "minimist": {
                    "severity": "moderate",
                    "via": ["npm:minimist:20200917"],
                },
            }
        })
        with patch.object(tools_mod, "_which", return_value="npm"), \
             patch.object(tools_mod, "_run", return_value=_fake_proc(payload, returncode=1)):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_audit(js_detected=True)
        self.assertEqual(st.status, "ok")
        self.assertEqual(len(findings), 2)
        by_id = {f.rule_id: f for f in findings}
        self.assertEqual(by_id["npm:lodash"].severity, "high")
        self.assertEqual(by_id["npm:minimist"].severity, "medium")
        self.assertIn("Prototype Pollution", by_id["npm:lodash"].message)

    def test_skipped_without_lockfile(self):
        (self.root / "package-lock.json").unlink()
        with patch.object(tools_mod, "_which", return_value="npm"):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_audit(js_detected=True)
        self.assertEqual(st.status, "skipped")
        self.assertIn("package-lock.json", st.detail)

    def test_skipped_when_not_js(self):
        with patch.object(tools_mod, "_which", return_value="npm"):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_audit(js_detected=False)
        self.assertEqual(st.status, "skipped")


if __name__ == "__main__":
    unittest.main()
