"""Grade local Claude leftover paths: A cache / B identity / C sessions / D assets."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

_B_KEYS = ("claude_json", "credentials", "device_id", "partition", "oauth")
_C_KEYS = ("project", "history", "session", "file_history", "file-history")
_D_KEYS = ("skill", "plugin", "settings", "claude_md", "claudemd")
_A_KEYS = ("cache", "statsig", "telemetry", "vm_bundle", "log", "shell_snapshot", "shell-snapshot", "code_cache")


def classify_label(label: Any) -> str:
    lab = str(label or "").lower().replace("-", "_")
    if not lab:
        return "?"
    if any(key in lab for key in _B_KEYS):
        return "B"
    if any(key in lab for key in _C_KEYS):
        return "C"
    if any(key in lab for key in _D_KEYS):
        return "D"
    if any(key in lab for key in _A_KEYS):
        return "A"
    return "?"


def summarize_inventory(artifacts: Iterable[Any]) -> Dict[str, Dict[str, int]]:
    summary = {key: {"count": 0, "bytes": 0} for key in ("A", "B", "C", "D")}
    for row in artifacts or []:
        if not isinstance(row, Mapping) or row.get("Present") is not True:
            continue
        category = str(row.get("Category") or classify_label(row.get("Label"))).upper()
        if category not in summary:
            continue
        size = row.get("SizeBytes") or 0
        try:
            size_i = int(size)
        except (TypeError, ValueError):
            size_i = 0
        summary[category]["count"] += 1
        summary[category]["bytes"] += max(size_i, 0)
    return summary


def _fmt_bytes(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}GB"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f}KB"
    return f"{n}B"


def collect_residue_check(claude: Mapping[str, Any], builder) -> None:
    artifacts = claude.get("LocalArtifacts")
    if not isinstance(artifacts, list):
        artifacts = []
    summary = summarize_inventory(artifacts)
    parts: List[str] = []
    for key, title in (
        ("A", "缓存"),
        ("B", "身份"),
        ("C", "会话"),
        ("D", "资产"),
    ):
        row = summary[key]
        if row["count"]:
            parts.append(f"{key}{title} {row['count']}项/{_fmt_bytes(row['bytes'])}")
    has_abc = any(summary[key]["count"] for key in ("A", "B", "C"))
    if not parts:
        builder.add(
            "privacy.residue_inventory",
            "Local Claude residue inventory",
            "privacy",
            "pass",
            "info",
            "没有观察到常见的本机 Claude 残留目录。",
            "",
        )
        return
    if has_abc:
        explanation = "本机残留分级：" + "；".join(parts) + "。只报路径类别和体积，不读内容、不删除。"
        status = "unknown"
    else:
        explanation = "本机只有资产类残留（D）：" + "；".join(parts) + "。"
        status = "pass"
    builder.add(
        "privacy.residue_inventory",
        "Local Claude residue inventory",
        "privacy",
        status,
        "info",
        explanation,
        "需要腾地方或换号时，按 A 缓存 → C 会话 → B 身份 的顺序自己删；D 是 skills/设置，默认留着。",
    )
