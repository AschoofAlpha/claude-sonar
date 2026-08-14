"""代码仓库安全扫描主流程编排。

run_repo_scan() 是主 agent 在 CLI 里调用的唯一入口：
  栈检测 -> 外部工具编排（graceful degradation）-> 去重指纹
  -> 0-100 加权评分 -> 高严重度修复建议 -> baseline 对比 -> SARIF 导出。

本模块不修改任何文件（SARIF 为显式指定路径才写出），
不进入主 audit checks/schema，输出独立于网络审计。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .baseline import diff_baseline, load_baseline
from .models import Finding, ScanResult, StackInfo, ToolStatus
from .sarif import findings_to_sarif, write_sarif
from .scoring import compute_score
from .stack import scan_stack
from .suggest import suggestion_for
from .tools import ToolRunner

try:
    from ..__version__ import __version__ as _PKG_VERSION
except Exception:  # pragma: no cover
    _PKG_VERSION = ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """按指纹去重（不同工具对同一处问题的重复报告只算一次）。"""
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        f.compute_fingerprint()
        if f.fingerprint and f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    return unique


def _attach_suggestions(findings: List[Finding]) -> None:
    """为高严重度 finding 附上人类可读修复建议（不自动改文件）。"""
    for f in findings:
        if f.severity in ("critical", "high"):
            f.suggestion = suggestion_for(f.to_dict())


def run_repo_scan(
    target_path: Union[str, Path],
    use_tools: bool = True,
    baseline_path: Optional[Union[str, Path]] = None,
    json_out: bool = False,
    sarif_path: Optional[Union[str, Path]] = None,
    timeout: Optional[Dict[str, int]] = None,
) -> Union[ScanResult, Dict[str, Any]]:
    """对目标目录执行一次完整的代码仓库安全扫描。

    参数：
      target_path  目标仓库目录（必须存在）
      use_tools    True 时编排外部工具（semgrep/gitleaks/pip-audit/npm audit），
                   缺工具自动跳过并注明，绝不报错退出；False 时只做栈检测。
      baseline_path 上次扫描 JSON 结果路径（--baseline），用于新增/修复/恶化对比。
      json_out     True 时返回可直接序列化的 dict（--json），否则返回 ScanResult。
      sarif_path   指定时导出 SARIF 2.1.0 文件（--sarif PATH）。
      timeout      可选 {工具名: 秒} 覆盖默认超时。

    返回：ScanResult（json_out=False）或 dict（json_out=True）。
    异常：目标目录不存在/不是目录时抛 ValueError（由 CLI 层转成友好报错）。
    """
    target = Path(target_path).expanduser()
    if not target.exists():
        raise ValueError(f"目标目录不存在：{target}")
    if not target.is_dir():
        raise ValueError(f"目标不是目录：{target}")
    target = target.resolve()

    notes: List[str] = []
    stack = scan_stack(target)
    languages = {s.language for s in stack}

    findings: List[Finding] = []
    tools: List[ToolStatus] = []
    if use_tools:
        runner = ToolRunner(target, timeout_override=timeout)
        f, tools, tool_notes = runner.run_all(languages, target_display=str(target))
        findings = f
        notes += tool_notes
    else:
        notes.append("外部工具未启用（use_tools=False），仅做了技术栈检测，未执行安全扫描。")

    findings = _dedupe(findings)
    _attach_suggestions(findings)

    scored = compute_score(findings)

    baseline: Optional[Dict[str, Any]] = None
    if baseline_path:
        base, err = load_baseline(baseline_path)
        if err:
            notes.append(f"baseline 对比跳过：{err}")
        else:
            base["_baseline_path"] = str(Path(baseline_path))
            baseline = diff_baseline(findings, base, scored["score"])

    sarif: Optional[Dict[str, Any]] = None
    if sarif_path:
        try:
            partial = {
                "findings": [f.to_dict() for f in findings],
                "score": scored["score"],
            }
            sarif_doc = findings_to_sarif(partial, tool_version=_PKG_VERSION)
            write_sarif(sarif_path, sarif_doc)
            sarif = {
                "path": str(Path(sarif_path)),
                "written": True,
                "results": len(findings),
            }
        except OSError as exc:
            sarif = {"path": str(sarif_path), "written": False, "error": str(exc)}
            notes.append(f"SARIF 导出失败：{exc}")

    result = ScanResult(
        target=str(target),
        generated_at=_now_iso(),
        stack=stack,
        tools=tools,
        findings=findings,
        score=scored["score"],
        grade=scored["grade"],
        grade_label=scored["grade_label"],
        distribution=scored["distribution"],
        baseline=baseline,
        sarif=sarif,
        notes=notes,
    )
    if json_out:
        return result.to_dict()
    return result


def result_to_report(result: Union[ScanResult, Dict[str, Any]]) -> str:
    """把扫描结果渲染成中文 Markdown 报告（独立可测的渲染函数）。"""
    from .report import render_report

    data = result if isinstance(result, dict) else result.to_dict()
    return render_report(data)


__all__ = [
    "run_repo_scan",
    "result_to_report",
    "scan_stack",
    "compute_score",
    "diff_baseline",
    "load_baseline",
    "findings_to_sarif",
    "write_sarif",
    "suggestion_for",
    "ToolRunner",
    "Finding",
    "StackInfo",
    "ToolStatus",
    "ScanResult",
]
