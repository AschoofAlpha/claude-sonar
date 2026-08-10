"""Markdown report formatter and three-tier action classification.

Maps AuditCheck rows into Must fix / Optional consistency / Leave alone
per SKILL.md Report Format. Pure presentation — no collector I/O.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

# Checks that indicate routing/DNS leak risk when not passing.
_LEAKISH_IDS = frozenset({
    "network.allow_lan",
    "network.dns",
    "network.dns_mode",
    "network.dns_hijack",
    "network.strict_route",
    "network.dns_physical_resolver",
    "network.teredo",
    "network.ipv6_binding",
    "network.dns_respect_rules",
})

# Non-leak consistency / preference signals.
_OPTIONAL_IDS = frozenset({
    "system.locale",
    "system.timezone",
    "network.tun",
    "network.tun_stack",
    "network.env_proxy",
    "network.dns_ipv6",
    "network.dns_encrypted",
    "privacy.telemetry",
    "privacy.errors",
    "privacy.nonessential",
    "privacy.prompt_history",
    "privacy.subprocess_scrub",
    "privacy.otel_user_prompts",
    "privacy.otel_tool_content",
    "privacy.otel_tool_details",
    "privacy.otel_raw_api",
})

_ACTION_ORDER = ("must_fix", "optional_consistency", "leave_alone")
_ACTION_TITLES = {
    "must_fix": "Must fix",
    "optional_consistency": "Optional consistency",
    "leave_alone": "Leave alone",
}
_SEVERITY_MUST = frozenset({"medium", "high", "critical"})


def _field(check: Any, name: str, default: Any = None) -> Any:
    if isinstance(check, Mapping):
        return check.get(name, default)
    return getattr(check, name, default)


def status_reason(check: Any) -> str:
    """Return a short subtype tag for unknown/optional checks.

    Encoded in explanation as ``[not_configured] ...`` when applicable;
    otherwise empty. Does not alter the AuditCheck schema.
    """
    explanation = str(_field(check, "explanation", "") or "")
    stripped = explanation.lstrip()
    if stripped.startswith("[") and "]" in stripped:
        tag = stripped[1:stripped.index("]")]
        if tag:
            return tag
    confidence = str(_field(check, "confidence", "") or "")
    status = str(_field(check, "status", "") or "")
    if status == "unknown" and confidence == "unknown":
        check_id = str(_field(check, "id", "") or "")
        if check_id.startswith("privacy."):
            return "not_configured"
    return ""


def classify_action(check: Any) -> str:
    """Classify a check into must_fix | optional_consistency | leave_alone."""
    status = str(_field(check, "status", "") or "")
    severity = str(_field(check, "severity", "info") or "info")
    check_id = str(_field(check, "id", "") or "")
    explanation = str(_field(check, "explanation", "") or "")
    reason = status_reason(check)

    if status == "fail":
        return "must_fix"
    if status == "warning" and severity in _SEVERITY_MUST:
        return "must_fix"
    if status in ("fail", "warning") and check_id in _LEAKISH_IDS:
        return "must_fix"

    if check_id in ("system.locale", "system.timezone"):
        if status == "pass":
            return "leave_alone"
        return "optional_consistency"

    if check_id == "network.tun" and status in ("unknown", "warning"):
        return "optional_consistency"

    if reason == "not_configured" or "[not_configured]" in explanation:
        return "optional_consistency"

    if check_id in _OPTIONAL_IDS and status in ("unknown", "warning"):
        return "optional_consistency"

    if status == "pass":
        return "leave_alone"

    if status == "warning" and severity in ("low", "info"):
        # Non-leakish low warnings still surface as optional consistency
        if check_id not in _LEAKISH_IDS:
            return "optional_consistency"

    if status in ("unknown", "skipped"):
        return "leave_alone"

    return "leave_alone"


def group_checks(checks: Iterable[Any]) -> Dict[str, List[Any]]:
    """Group checks by classify_action() result."""
    groups: Dict[str, List[Any]] = {key: [] for key in _ACTION_ORDER}
    for check in checks:
        action = classify_action(check)
        if action not in groups:
            action = "leave_alone"
        groups[action].append(check)
    return groups


def _evidence_cell(check: Any) -> str:
    items = _field(check, "evidence", None) or []
    if not items:
        return "—"
    parts = []
    for item in items[:3]:
        if isinstance(item, Mapping):
            desc = item.get("description") or item.get("type") or ""
        else:
            desc = getattr(item, "description", None) or getattr(item, "type", "") or ""
        desc = str(desc).replace("|", "/").strip()
        if desc:
            parts.append(desc)
    return "; ".join(parts) if parts else "—"


def _md_escape_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").replace("|", "/")
    return text.strip() or "—"


def format_report(checks: Sequence[Any], summary: Optional[Mapping[str, Any]] = None) -> str:
    """Render checks as a compact markdown report (table + three sections)."""
    checks = list(checks or [])
    lines: List[str] = ["# Claude Shield Audit Report", ""]

    if summary:
        parts = []
        for key in ("critical", "high", "medium", "low", "info"):
            if key in summary:
                parts.append(f"{key}={summary[key]}")
        if parts:
            lines.append("Summary: " + ", ".join(parts))
            lines.append("")

    lines.append("| signal | status | confidence | evidence | action |")
    lines.append("| --- | --- | --- | --- | --- |")
    for check in checks:
        action = classify_action(check)
        check_id = str(_field(check, "id", "") or "")
        check_title = str(_field(check, "title", "") or "").strip()
        signal = check_title or check_id
        if check_title and check_id and check_title != check_id:
            signal = f"{check_title} ({check_id})"
        lines.append(
            "| {signal} | {status} | {confidence} | {evidence} | {action} |".format(
                signal=_md_escape_cell(signal),
                status=_md_escape_cell(_field(check, "status", "")),
                confidence=_md_escape_cell(_field(check, "confidence", "")),
                evidence=_md_escape_cell(_evidence_cell(check)),
                action=_md_escape_cell(action),
            )
        )
    lines.append("")

    groups = group_checks(checks)
    for key in _ACTION_ORDER:
        section_title = _ACTION_TITLES[key]
        lines.append(f"## {section_title}")
        lines.append("")
        items = groups.get(key) or []
        if not items:
            lines.append("_None._")
            lines.append("")
            continue
        for check in items:
            check_id = _field(check, "id", "unknown")
            check_title = str(_field(check, "title", "") or "").strip()
            status = _field(check, "status", "")
            explanation = str(_field(check, "explanation", "") or "").strip()
            recommendation = str(_field(check, "recommendation", "") or "").strip()
            label = check_title or check_id
            if check_title and check_id and check_title != check_id:
                line = f"- **{check_title}** (`{check_id}`, {status}): {explanation or '—'}"
            else:
                line = f"- **{label}** ({status}): {explanation or '—'}"
            lines.append(line)
            if recommendation and key != "leave_alone":
                lines.append(f"  - recommendation: {recommendation}")
        lines.append("")

    lines.append(
        "_Uncertainty is stated explicitly. Reputation scores and static "
        "configuration alone are not proof of a leak._"
    )
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "classify_action",
    "format_report",
    "group_checks",
    "status_reason",
]
