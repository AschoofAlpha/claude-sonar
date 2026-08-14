"""reposcan 中文 Markdown 报告渲染（复用项目报告风格：表格 + 中文说明列）。

风格约定与主 audit 报告一致：技术名词保留英文、说明用中文、
分数以表格呈现、语气平和（提示性而非恐吓性）。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_SEV_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
_SEV_MEANING = {
    "critical": "可直接利用的漏洞或密钥泄露",
    "high": "大概率可利用的安全缺陷",
    "medium": "需特定条件利用或影响有限",
    "low": "不良实践或潜在风险",
}
_WEIGHTS = {"critical": 25, "high": 15, "medium": 6, "low": 2}
_STATUS_ZH = {"ok": "✅ 已运行", "skipped": "⏭️ 已跳过", "error": "❌ 出错"}

_MAX_FINDING_ROWS = 30
_MAX_SUGGESTIONS = 8


def _esc(text: Any) -> str:
    """转义表格单元格里的管道符与换行。"""
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def _status_text(st: Dict[str, Any]) -> str:
    return _STATUS_ZH.get(st.get("status"), "未知")


def render_report(result: Dict[str, Any], lang: str = "zh") -> str:
    """渲染扫描结果为中文 Markdown 报告。lang 目前仅支持 zh（预留 en）。"""
    lines: List[str] = []
    target = str(result.get("target") or "")
    score = int(result.get("score", 0))
    grade = result.get("grade") or "-"
    grade_label = result.get("grade_label") or ""
    dist = result.get("distribution") or {}
    findings = result.get("findings") or []
    stack = result.get("stack") or []
    tools = result.get("tools") or []
    baseline = result.get("baseline")
    sarif = result.get("sarif")
    notes = result.get("notes") or []

    lines.append("# 代码仓库安全扫描报告")
    lines.append("")
    lines.append(f"- 扫描目标：`{_esc(target)}`")
    lines.append(f"- 生成时间：{_esc(result.get('generated_at'))}")
    lines.append(f"- 结果格式：claude-sonar reposcan（schema {result.get('schema_version', 'reposcan/1')}）")
    lines.append("")

    # ---------------- 代码安全分 ----------------
    lines.append("## 代码安全分")
    lines.append("")
    lines.append(f"**{score} / 100（等级 {grade}）** — {grade_label}")
    lines.append("")
    lines.append("> 分数是相对参考而非安全认证：低分不等于已被入侵，高分也不等于绝对安全。")
    lines.append("> 建议结合代码上下文人工复核每条发现。")
    lines.append("")
    lines.append("| 严重程度 | 数量 | 权重 | 含义 |")
    lines.append("| --- | --- | --- | --- |")
    for sev in ("critical", "high", "medium", "low"):
        count = int(dist.get(sev, 0))
        lines.append(
            f"| {_SEV_ZH[sev]} ({sev}) | {count} | -{_WEIGHTS[sev]}/条 | {_SEV_MEANING[sev]} |"
        )
    lines.append("")

    # ---------------- 技术栈 ----------------
    lines.append("## 检测到的技术栈")
    lines.append("")
    if stack:
        lines.append("| 语言 | 包管理器 | 依据文件 |")
        lines.append("| --- | --- | --- |")
        for s in stack:
            files = "、".join(str(f) for f in (s.get("files") or [])[:5])
            if len(s.get("files") or []) > 5:
                files += " 等"
            lines.append(
                f"| {_esc(s.get('language'))} | {_esc(s.get('package_manager'))} | {_esc(files)} |"
            )
    else:
        lines.append("未检测到已知的 lockfile / manifest / 源码文件。")
    lines.append("")

    # ---------------- 工具状态 ----------------
    lines.append("## 扫描工具状态")
    lines.append("")
    lines.append("| 工具 | 状态 | 说明 |")
    lines.append("| --- | --- | --- |")
    for st in tools:
        detail = _esc(st.get("detail"))
        if st.get("status") != "ok" and st.get("install_hint"):
            detail += f"；安装：{_esc(st.get('install_hint'))}"
        lines.append(f"| {_esc(st.get('display', st.get('name')))} | {_status_text(st)} | {detail} |")
    lines.append("")
    for note in notes:
        lines.append(f"> 注：{_esc(note)}")
    if notes:
        lines.append("")

    # ---------------- 发现明细 ----------------
    lines.append(f"## 发现明细（共 {len(findings)} 项）")
    lines.append("")
    if findings:
        shown = findings[:_MAX_FINDING_ROWS]
        lines.append("| 严重程度 | 工具 / 规则 | 位置 | 说明 |")
        lines.append("| --- | --- | --- | --- |")
        for f in shown:
            loc = _esc(f.get("path")) or "-"
            if f.get("line"):
                loc += f":{f.get('line')}"
            lines.append(
                f"| {_SEV_ZH.get(f.get('severity'), f.get('severity'))} "
                f"| {_esc(f.get('tool'))}: {_esc(f.get('rule_id'))} "
                f"| {loc} "
                f"| {_esc(str(f.get('message'))[:120])} |"
            )
        if len(findings) > _MAX_FINDING_ROWS:
            lines.append("")
            lines.append(f"（其余 {len(findings) - _MAX_FINDING_ROWS} 项见 JSON / SARIF 输出）")
    else:
        lines.append("未发现安全问题。")
    lines.append("")

    # ---------------- 修复建议 ----------------
    lines.append("## 修复建议（高严重度）")
    lines.append("")
    high = [f for f in findings if f.get("severity") in ("critical", "high")]
    if high:
        lines.append("以下建议仅供人工参考，本工具不会自动修改任何文件。")
        lines.append("")
        for i, f in enumerate(high[:_MAX_SUGGESTIONS]):
            loc = _esc(f.get("path")) or "-"
            if f.get("line"):
                loc += f":{f.get('line')}"
            suggestion = str(f.get("suggestion") or "").strip()
            lines.append(f"### {i + 1}. {_esc(f.get('rule_id'))} — {loc}")
            lines.append("")
            lines.append(f"- 问题：{_esc(str(f.get('message'))[:200])}")
            if suggestion:
                lines.append(f"- 建议：{suggestion}")
            lines.append("")
        if len(high) > _MAX_SUGGESTIONS:
            lines.append(f"（其余 {len(high) - _MAX_SUGGESTIONS} 项高危发现见 JSON 输出）")
    else:
        lines.append("当前没有高危（high/critical）发现，无需紧急处理。")
    lines.append("")

    # ---------------- baseline 对比 ----------------
    if baseline:
        lines.append("## 与上次扫描对比（baseline）")
        lines.append("")
        lines.append("| 指标 | 上次 | 本次 | 变化 |")
        lines.append("| --- | --- | --- | --- |")
        prev_score = int(baseline.get("previous_score", 0))
        delta = int(baseline.get("score_delta", 0))
        delta_s = f"+{delta}" if delta > 0 else str(delta)
        lines.append(f"| 代码安全分 | {prev_score} | {score} | {delta_s} |")
        lines.append(f"| 新增问题 | - | {baseline.get('added', 0)} | - |")
        lines.append(f"| 已修复 | - | {baseline.get('fixed', 0)} | - |")
        lines.append(f"| 严重度恶化 | - | {baseline.get('worsened', 0)} | - |")
        lines.append("")
        added_list = baseline.get("added_findings") or []
        if added_list:
            lines.append("新增问题示例：")
            lines.append("")
            for f in added_list[:5]:
                loc = _esc(f.get("path")) or "-"
                if f.get("line"):
                    loc += f":{f.get('line')}"
                lines.append(f"- {_SEV_ZH.get(f.get('severity'), f.get('severity'))} `{_esc(f.get('rule_id'))}` {loc}")
            lines.append("")

    # ---------------- SARIF ----------------
    if sarif:
        if sarif.get("written"):
            lines.append(f"SARIF 2.1.0 已导出：`{_esc(sarif.get('path'))}`")
        else:
            lines.append(f"SARIF 导出失败：{_esc(sarif.get('error'))}")
        lines.append("")

    # ---------------- 尾注 ----------------
    lines.append("---")
    lines.append("")
    lines.append("**说明**：本报告基于静态规则与公开漏洞数据库自动生成，可能存在误报；")
    lines.append("分数只是参考，不是安全认证。建议结合代码上下文人工复核，")
    lines.append("并优先处理「严重 / 高危」项。")
    lines.append("")
    return "\n".join(lines)
