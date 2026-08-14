"""报告渲染测试：中文 Markdown 结构、表格、修复建议、baseline 段落、温和语气。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from claude_sonar.reposcan.report import render_report


def _result(**overrides):
    base = {
        "schema_version": "reposcan/1",
        "target": "/repo/demo",
        "generated_at": "2026-08-13T10:00:00+08:00",
        "stack": [
            {"language": "Python", "package_manager": "pip + Poetry",
             "files": ["requirements.txt", "pyproject.toml"]},
        ],
        "tools": [
            {"name": "semgrep", "display": "semgrep（SAST 静态分析）",
             "status": "ok", "available": True, "detail": "已完成，检出 2 项",
             "findings_count": 2, "install_hint": ""},
            {"name": "gitleaks", "display": "gitleaks（密钥/敏感信息扫描）",
             "status": "skipped", "available": False, "detail": "工具未安装，本次跳过密钥扫描",
             "findings_count": 0, "install_hint": "winget install gitleaks.gitleaks"},
        ],
        "findings": [
            {"tool": "semgrep", "rule_id": "py-sql-injection-format", "severity": "high",
             "path": "app.py", "line": 42, "message": "SQL 查询使用字符串格式化拼接",
             "cwe": "CWE-89", "fingerprint": "aa", "suggestion": "使用参数化查询"},
            {"tool": "semgrep", "rule_id": "py-weak-crypto", "severity": "medium",
             "path": "util.py", "line": 7, "message": "弱加密", "cwe": None,
             "fingerprint": "bb", "suggestion": ""},
        ],
        "score": 79,
        "grade": "B",
        "grade_label": "良好（存在少量中低危问题，建议安排修复）",
        "distribution": {"critical": 0, "high": 1, "medium": 1, "low": 0},
        "baseline": None,
        "sarif": None,
        "notes": [],
    }
    base.update(overrides)
    return base


class TestReportRendering(unittest.TestCase):
    def test_title_and_score(self):
        md = render_report(_result())
        self.assertIn("# 代码仓库安全扫描报告", md)
        self.assertIn("**79 / 100（等级 B）**", md)
        self.assertIn("良好", md)

    def test_distribution_table_zh(self):
        md = render_report(_result())
        self.assertIn("| 严重程度 | 数量 | 权重 | 含义 |", md)
        self.assertIn("| 严重 (critical) | 0 | -25/条 |", md)
        self.assertIn("| 高危 (high) | 1 | -15/条 |", md)
        self.assertIn("| 中危 (medium) | 1 | -6/条 |", md)
        self.assertIn("| 低危 (low) | 0 | -2/条 |", md)

    def test_stack_table(self):
        md = render_report(_result())
        self.assertIn("| 语言 | 包管理器 | 依据文件 |", md)
        self.assertIn("| Python | pip + Poetry |", md)

    def test_tool_status_table_with_install_hint(self):
        md = render_report(_result())
        self.assertIn("✅ 已运行", md)
        self.assertIn("⏭️ 已跳过", md)
        self.assertIn("winget install gitleaks.gitleaks", md)

    def test_findings_table(self):
        md = render_report(_result())
        self.assertIn("| 严重程度 | 工具 / 规则 | 位置 | 说明 |", md)
        self.assertIn("app.py:42", md)
        self.assertIn("py-sql-injection-format", md)
        self.assertIn("util.py:7", md)
        # 表格单元格管道符转义
        self.assertNotIn("SQL 查询使用字符串格式化拼接 | 高危", md)

    def test_fix_suggestion_section_for_high(self):
        md = render_report(_result())
        self.assertIn("## 修复建议（高严重度）", md)
        self.assertIn("### 1. py-sql-injection-format — app.py:42", md)
        self.assertIn("使用参数化查询", md)
        self.assertIn("不会自动修改任何文件", md)

    def test_no_high_findings_shows_calm_note(self):
        md = render_report(_result(
            findings=[],
            distribution={"critical": 0, "high": 0, "medium": 0, "low": 0},
            score=100, grade="A",
        ))
        self.assertIn("当前没有高危（high/critical）发现", md)
        self.assertIn("100", md)

    def test_baseline_section(self):
        md = render_report(_result(baseline={
            "added": 1, "fixed": 2, "worsened": 0,
            "previous_score": 70, "score_delta": 9,
            "added_findings": [{"rule_id": "x", "severity": "high", "path": "a.py", "line": 1}],
        }))
        self.assertIn("## 与上次扫描对比（baseline）", md)
        self.assertIn("| 新增问题 | - | 1 | - |", md)
        self.assertIn("| 已修复 | - | 2 | - |", md)
        self.assertIn("| 严重度恶化 | - | 0 | - |", md)

    def test_sarif_note(self):
        md = render_report(_result(sarif={"path": "/tmp/r.sarif", "written": True}))
        self.assertIn("SARIF 2.1.0 已导出", md)

    def test_calm_footer(self):
        md = render_report(_result())
        self.assertIn("可能存在误报", md)
        self.assertIn("不是安全认证", md)

    def test_empty_stack_message(self):
        md = render_report(_result(stack=[]))
        self.assertIn("未检测到已知的 lockfile", md)

    def test_row_cap(self):
        findings = [
            {"tool": "semgrep", "rule_id": f"r{i}", "severity": "low",
             "path": "a.py", "line": i, "message": "m", "fingerprint": str(i)}
            for i in range(35)
        ]
        md = render_report(_result(findings=findings))
        self.assertIn("其余 5 项见 JSON / SARIF 输出", md)


if __name__ == "__main__":
    unittest.main()
