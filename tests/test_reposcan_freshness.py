"""Freshness（依赖过期检测）测试：semver 分级、汇总行为、编排降级路径。"""
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
from claude_sonar.reposcan.tools import ToolRunner, _freshness_findings, _semver_tier


def _fake_proc(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["fake"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class TestSemverTier(unittest.TestCase):
    def test_tiers(self):
        self.assertEqual(_semver_tier("1.2.3", "2.0.0"), "MAJOR")
        self.assertEqual(_semver_tier("1.2.3", "1.9.0"), "MINOR")
        self.assertEqual(_semver_tier("1.2.3", "1.2.9"), "PATCH")
        self.assertEqual(_semver_tier("1.2.3", "1.2.3"), "PATCH")  # 相同不该被调用

    def test_nonstandard_prefixes(self):
        self.assertEqual(_semver_tier("v1.0.0", "2.0.0"), "MAJOR")
        self.assertEqual(_semver_tier("^1.0.0", "1.5.0"), "MINOR")


class TestFreshnessFindings(unittest.TestCase):
    def test_major_per_row_minor_patch_aggregated(self):
        rows = [
            {"name": "a", "current": "1.0.0", "latest": "2.0.0"},
            {"name": "b", "current": "1.0.0", "latest": "3.0.0"},
            {"name": "c", "current": "1.0.0", "latest": "1.5.0"},
            {"name": "d", "current": "1.0.0", "latest": "1.0.1"},
        ]
        fs = _freshness_findings(rows, "package.json")
        by_rule = {}
        for f in fs:
            by_rule.setdefault(f.rule_id, []).append(f)
        self.assertEqual(len(by_rule["OUTDATED-MAJOR"]), 2)  # 逐条
        self.assertEqual(len(by_rule["OUTDATED-MINOR"]), 1)  # 汇总
        self.assertEqual(len(by_rule["OUTDATED-PATCH"]), 1)  # 汇总
        self.assertEqual(fs[0].severity, "low")
        self.assertIn("c: 1.0.0 → 1.5.0", by_rule["OUTDATED-MINOR"][0].message)

    def test_up_to_date_and_unknown_skipped(self):
        fs = _freshness_findings([
            {"name": "a", "current": "1.0.0", "latest": "1.0.0"},
            {"name": "b", "current": "1.0.0", "latest": "?"},
        ], "package.json")
        self.assertEqual(fs, [])


class TestNpmOutdated(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="reposcan-fresh-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_package_json_skipped(self):
        with patch.object(tools_mod, "_which", return_value="npm"):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_outdated(js_detected=True)
        self.assertEqual(findings, [])
        self.assertEqual(st.status, "skipped")

    def test_npm_missing_skipped(self):
        with patch.object(tools_mod, "_which", return_value=None):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_outdated(js_detected=True)
        self.assertEqual(st.status, "skipped")
        self.assertTrue(st.install_hint)

    def test_up_to_date_ok(self):
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        with patch.object(tools_mod, "_which", return_value="npm"), \
             patch.object(tools_mod, "_run",
                          return_value=_fake_proc(stdout="", returncode=1)):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_outdated(js_detected=True)
        self.assertEqual(findings, [])
        self.assertEqual(st.status, "ok")
        self.assertIn("无过期", st.detail)

    def test_outdated_findings(self):
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        payload = json.dumps({
            "lodash": {"current": "4.17.20", "latest": "5.0.0"},
            "chalk": {"current": "5.0.0", "latest": "5.3.0"},
        })
        with patch.object(tools_mod, "_which", return_value="npm"), \
             patch.object(tools_mod, "_run",
                          return_value=_fake_proc(stdout=payload, returncode=1)):
            runner = ToolRunner(self.root)
            findings, st = runner.run_npm_outdated(js_detected=True)
        self.assertEqual(st.status, "ok")
        self.assertTrue(any(f.rule_id == "OUTDATED-MAJOR" for f in findings))
        self.assertTrue(any(f.rule_id == "OUTDATED-MINOR" for f in findings))
        self.assertIn("MAJOR 1 个", st.detail)


class TestPipOutdated(unittest.TestCase):
    def test_no_python_skipped(self):
        runner = ToolRunner(Path("."))
        findings, st = runner.run_pip_outdated(python_detected=False)
        self.assertEqual(findings, [])
        self.assertEqual(st.status, "skipped")

    def test_empty_env_ok(self):
        with patch.object(tools_mod, "_which", return_value="pip"), \
             patch.object(tools_mod, "_run",
                          return_value=_fake_proc(stdout="[]", returncode=0)):
            runner = ToolRunner(Path("."))
            findings, st = runner.run_pip_outdated(python_detected=True)
        self.assertEqual(findings, [])
        self.assertEqual(st.status, "ok")

    def test_outdated_findings(self):
        payload = json.dumps([
            {"name": "requests", "version": "2.28.0", "latest_version": "3.0.0"},
        ])
        with patch.object(tools_mod, "_which", return_value="pip"), \
             patch.object(tools_mod, "_run",
                          return_value=_fake_proc(stdout=payload, returncode=0)):
            runner = ToolRunner(Path("."))
            findings, st = runner.run_pip_outdated(python_detected=True)
        self.assertEqual(st.status, "ok")
        self.assertTrue(any(f.rule_id == "OUTDATED-MAJOR" for f in findings))
        self.assertIn("非项目 venv", st.detail)


class TestRunAllIncludesFreshness(unittest.TestCase):
    def test_status_count_is_six(self):
        with patch.object(tools_mod, "_which", return_value=None):
            runner = ToolRunner(Path("."))
            findings, statuses, notes = runner.run_all({"Python", "JavaScript/TypeScript"})
        self.assertEqual(len(statuses), 6)  # gitleaks/semgrep/pip-audit/npm/2×freshness
        self.assertTrue(all(st.status == "skipped" for st in statuses))
