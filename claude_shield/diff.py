"""Compare two audit check lists and render a markdown diff.

Pure presentation helpers — no collector I/O. Accepts AuditCheck objects
or plain dict rows (as found inside ``report_dict`` JSON).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


def _field(check: Any, name: str, default: Any = None) -> Any:
    if isinstance(check, Mapping):
        return check.get(name, default)
    return getattr(check, name, default)


def _check_id(check: Any) -> str:
    return str(_field(check, "id", "") or "").strip()


def _check_status(check: Any) -> str:
    return str(_field(check, "status", "") or "").strip().lower()


def _check_title(check: Any) -> str:
    title = str(_field(check, "title", "") or "").strip()
    if title:
        return title
    return _check_id(check) or "—"


def _index_by_id(checks: Iterable[Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for check in checks or []:
        cid = _check_id(check)
        if not cid:
            continue
        # Last write wins if duplicates appear (stable for dict/JSON loads).
        out[cid] = check
    return out


def load_checks_from_report_dict(report_dict: Optional[Mapping[str, Any]]) -> List[Any]:
    """Extract the ``checks`` list from a report_dict / AuditReport JSON shape.

    Accepts:
    - ``{"checks": [...]}`` (top-level report_dict)
    - ``{"report": {"checks": [...]}}`` / ``{"report_dict": {"checks": [...]}}``
    - a bare list of checks
    - ``None`` → empty list
    """
    if report_dict is None:
        return []
    if isinstance(report_dict, list):
        return list(report_dict)
    if not isinstance(report_dict, Mapping):
        return []

    if isinstance(report_dict.get("checks"), list):
        return list(report_dict["checks"])

    for nested_key in ("report_dict", "report", "audit", "data"):
        nested = report_dict.get(nested_key)
        if isinstance(nested, Mapping) and isinstance(nested.get("checks"), list):
            return list(nested["checks"])
        if isinstance(nested, list):
            # Some wrappers put checks directly under a key.
            return list(nested)

    return []


def diff_audits(
    before_checks: Sequence[Any],
    after_checks: Sequence[Any],
) -> Dict[str, Any]:
    """Diff two check lists by id.

    Returns
    -------
    dict
        ``added``: list of after-only check summaries
        ``removed``: list of before-only check summaries
        ``status_changed``: list of ``{id, before, after, title}``
        ``unchanged``: count of ids present in both with same status
    """
    before_map = _index_by_id(before_checks)
    after_map = _index_by_id(after_checks)

    before_ids = set(before_map)
    after_ids = set(after_map)

    added: List[Dict[str, Any]] = []
    for cid in sorted(after_ids - before_ids):
        check = after_map[cid]
        added.append(
            {
                "id": cid,
                "status": _check_status(check),
                "title": _check_title(check),
            }
        )

    removed: List[Dict[str, Any]] = []
    for cid in sorted(before_ids - after_ids):
        check = before_map[cid]
        removed.append(
            {
                "id": cid,
                "status": _check_status(check),
                "title": _check_title(check),
            }
        )

    status_changed: List[Dict[str, Any]] = []
    unchanged = 0
    for cid in sorted(before_ids & after_ids):
        b_status = _check_status(before_map[cid])
        a_status = _check_status(after_map[cid])
        if b_status != a_status:
            status_changed.append(
                {
                    "id": cid,
                    "before": b_status,
                    "after": a_status,
                    "title": _check_title(after_map[cid]) or _check_title(before_map[cid]),
                }
            )
        else:
            unchanged += 1

    return {
        "added": added,
        "removed": removed,
        "status_changed": status_changed,
        "unchanged": unchanged,
    }


def _norm_lang(lang: Optional[str]) -> str:
    value = (lang or "zh").strip().lower()
    if value in ("en", "english"):
        return "en"
    return "zh"


def format_diff_markdown(diff: Mapping[str, Any], lang: str = "zh") -> str:
    """Render a ``diff_audits`` result as markdown tables."""
    lang = _norm_lang(lang)
    zh = lang == "zh"

    added = list(diff.get("added") or [])
    removed = list(diff.get("removed") or [])
    changed = list(diff.get("status_changed") or [])
    unchanged = diff.get("unchanged", 0)

    lines: List[str] = []
    if zh:
        lines.extend(
            [
                "# 审计对比",
                "",
                f"_新增 {len(added)} · 移除 {len(removed)} · 状态变化 {len(changed)} · 未变 {unchanged}_",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "# Audit diff",
                "",
                f"_added {len(added)} · removed {len(removed)} · status changed {len(changed)} · unchanged {unchanged}_",
                "",
            ]
        )

    # Status changes first — usually what operators care about.
    if zh:
        lines.append("## 状态变化")
    else:
        lines.append("## Status changed")
    lines.append("")
    if not changed:
        lines.append("_无。_" if zh else "_None._")
        lines.append("")
    else:
        if zh:
            lines.extend(["| 检查项 | 标题 | 之前 | 之后 |", "| --- | --- | --- | --- |"])
        else:
            lines.extend(["| id | title | before | after |", "| --- | --- | --- | --- |"])
        for row in changed:
            lines.append(
                "| {id} | {title} | {before} | {after} |".format(
                    id=_md_cell(row.get("id")),
                    title=_md_cell(row.get("title")),
                    before=_md_cell(row.get("before")),
                    after=_md_cell(row.get("after")),
                )
            )
        lines.append("")

    if zh:
        lines.append("## 新增")
    else:
        lines.append("## Added")
    lines.append("")
    if not added:
        lines.append("_无。_" if zh else "_None._")
        lines.append("")
    else:
        if zh:
            lines.extend(["| 检查项 | 标题 | 状态 |", "| --- | --- | --- |"])
        else:
            lines.extend(["| id | title | status |", "| --- | --- | --- |"])
        for row in added:
            lines.append(
                "| {id} | {title} | {status} |".format(
                    id=_md_cell(row.get("id")),
                    title=_md_cell(row.get("title")),
                    status=_md_cell(row.get("status")),
                )
            )
        lines.append("")

    if zh:
        lines.append("## 移除")
    else:
        lines.append("## Removed")
    lines.append("")
    if not removed:
        lines.append("_无。_" if zh else "_None._")
        lines.append("")
    else:
        if zh:
            lines.extend(["| 检查项 | 标题 | 状态 |", "| --- | --- | --- |"])
        else:
            lines.extend(["| id | title | status |", "| --- | --- | --- |"])
        for row in removed:
            lines.append(
                "| {id} | {title} | {status} |".format(
                    id=_md_cell(row.get("id")),
                    title=_md_cell(row.get("title")),
                    status=_md_cell(row.get("status")),
                )
            )
        lines.append("")

    return "\n".join(lines)


def _md_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").replace("|", "/")
    return text.strip() or "—"


def load_previous_report(path: str) -> Any:
    """Load a previous JSON report from disk (CLI ``--diff`` helper)."""
    import json
    from pathlib import Path

    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff_reports(previous: Any, current: Any) -> Dict[str, Any]:
    """Diff two report payloads (CLI / library convenience wrapper).

    Accepts report_dict, CLI ``--json`` payload, ``{checks: [...]}``, or bare
    check lists. Returns ``diff_audits`` shape plus a ``summary`` count dict
    for callers that prefer aggregate numbers.
    """
    before = load_checks_from_report_dict(previous)
    after = load_checks_from_report_dict(current)
    result = diff_audits(before, after)
    result["summary"] = {
        "added": len(result.get("added") or []),
        "removed": len(result.get("removed") or []),
        "changed": len(result.get("status_changed") or []),
        "unchanged": int(result.get("unchanged") or 0),
    }
    # Alias key used by some callers/tests.
    result.setdefault("changed", list(result.get("status_changed") or []))
    return result


__all__ = [
    "diff_audits",
    "diff_reports",
    "format_diff_markdown",
    "load_checks_from_report_dict",
    "load_previous_report",
]
