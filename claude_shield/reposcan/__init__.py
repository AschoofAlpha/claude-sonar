"""claude-shield 代码仓库安全扫描子模块（reposcan）。

独立于网络审计（不进入主 audit checks/schema），零第三方依赖，输出
中文 Markdown 报告 / JSON / SARIF 2.1.0。

入口：
    from claude_shield.reposcan import run_repo_scan, result_to_report

    result = run_repo_scan("path/to/repo", use_tools=True,
                           baseline_path=None, json_out=False, sarif_path=None)
    markdown = result_to_report(result)
"""

from __future__ import annotations

from .baseline import diff_baseline, load_baseline
from .models import Finding, ScanResult, StackInfo, ToolStatus
from .report import render_report
from .rules import (
    available_rule_files,
    manual_semgrep_hint,
    rule_files_for_languages,
    rules_dir,
)
from .sarif import findings_to_sarif, write_sarif
from .scanner import result_to_report, run_repo_scan
from .scoring import compute_score, grade_of, severity_distribution
from .stack import scan_stack
from .suggest import suggestion_for
from .tools import ToolRunner

__all__ = [
    "run_repo_scan",
    "result_to_report",
    "render_report",
    "scan_stack",
    "compute_score",
    "grade_of",
    "severity_distribution",
    "diff_baseline",
    "load_baseline",
    "findings_to_sarif",
    "write_sarif",
    "suggestion_for",
    "rules_dir",
    "available_rule_files",
    "rule_files_for_languages",
    "manual_semgrep_hint",
    "ToolRunner",
    "Finding",
    "StackInfo",
    "ToolStatus",
    "ScanResult",
]
