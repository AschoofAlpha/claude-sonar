"""baseline 对比：与上次 JSON 扫描结果对比，统计 新增 / 修复 / 恶化。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding, severity_rank


def load_baseline(path: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """读取上次扫描的 JSON 结果；失败返回 (None, 错误说明)。"""
    try:
        p = Path(path)
        if not p.is_file():
            return None, f"baseline 文件不存在：{p}"
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, TypeError) as exc:
        return None, f"baseline 文件不是合法 JSON：{exc}"
    except OSError as exc:
        return None, f"无法读取 baseline 文件：{exc}"
    if not isinstance(data, dict):
        return None, "baseline 文件结构不正确（应为扫描结果的 JSON 对象）"
    return data, None


def diff_baseline(
    new_findings: List[Finding],
    baseline: Dict[str, Any],
    new_score: int,
) -> Dict[str, Any]:
    """按指纹对比两次扫描，返回统计与明细。"""
    old_list = baseline.get("findings") or []
    old_by_fp: Dict[str, Dict[str, Any]] = {}
    for f in old_list:
        if isinstance(f, dict) and f.get("fingerprint"):
            old_by_fp[f["fingerprint"]] = f
    new_by_fp: Dict[str, Finding] = {}
    for f in new_findings:
        if f.fingerprint:
            new_by_fp[f.fingerprint] = f

    added = [f for fp, f in new_by_fp.items() if fp not in old_by_fp]
    fixed = [f for fp, f in old_by_fp.items() if fp not in new_by_fp]
    worsened = [
        f for fp, f in new_by_fp.items()
        if fp in old_by_fp
        and severity_rank(f.severity)
        > severity_rank(old_by_fp[fp].get("severity") or "low")
    ]
    try:
        old_score = int(baseline.get("score", 0))
    except (TypeError, ValueError):
        old_score = 0

    return {
        "path": baseline.get("_baseline_path", ""),
        "added": len(added),
        "fixed": len(fixed),
        "worsened": len(worsened),
        "score_delta": new_score - old_score,
        "previous_score": old_score,
        "added_findings": [f.to_dict() for f in added[:20]],
        "fixed_findings": [dict(f) for f in fixed[:20]],
        "worsened_findings": [f.to_dict() for f in worsened[:20]],
    }
