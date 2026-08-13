"""0-100 加权评分与严重度分布。

权重设计（每发现一条扣分，下限 0）：
  critical  -25 / 条
  high      -15 / 条
  medium    -6  / 条
  low       -2  / 条

等级划分：>=90 A 优秀；>=75 B 良好；>=60 C 一般；>=40 D 较差；<40 F 高风险。
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .models import SEVERITIES, Finding, normalize_severity

WEIGHTS: Dict[str, int] = {"critical": 25, "high": 15, "medium": 6, "low": 2}

_GRADES = [
    (90, "A", "优秀（暂未发现明显高危问题）"),
    (75, "B", "良好（存在少量中低危问题，建议安排修复）"),
    (60, "C", "一般（有需要关注的安全问题）"),
    (40, "D", "较差（存在高危问题，建议尽快处理）"),
    (0, "F", "高风险（发现严重安全问题，请优先处理）"),
]


def severity_distribution(findings: Iterable[Finding]) -> Dict[str, int]:
    """按 critical/high/medium/low 计数（未知严重度归入 low）。"""
    dist = {s: 0 for s in SEVERITIES}
    for f in findings:
        dist[normalize_severity(f.severity)] += 1
    return dist


def grade_of(score: int) -> "tuple[str, str]":
    for threshold, grade, label in _GRADES:
        if score >= threshold:
            return grade, label
    return "F", _GRADES[-1][2]


def compute_score(findings: Iterable[Finding]) -> Dict[str, Any]:
    """返回 {score, grade, grade_label, distribution, breakdown}。"""
    dist = severity_distribution(findings)
    penalty = sum(WEIGHTS[s] * dist[s] for s in SEVERITIES)
    score = max(0, 100 - penalty)
    grade, label = grade_of(score)
    return {
        "score": score,
        "grade": grade,
        "grade_label": label,
        "distribution": dist,
        "breakdown": {
            "penalty": penalty,
            "weights": dict(WEIGHTS),
            "counts": dict(dist),
        },
    }
