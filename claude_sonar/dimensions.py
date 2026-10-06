"""Compose existing audit checks into a conservative six-dimension matrix.

The matrix is a presentation layer inspired by browser privacy checklists.  It
does not run probes, calculate an IP reputation score, or make an account or
ban decision.  A dimension is ``unknown`` when the available checks do not
cover it or when a covered check is itself unknown.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .models import to_dict


DIMENSION_DEFINITIONS: Tuple[Dict[str, Any], ...] = (
    {
        "id": "exit_network",
        "label_zh": "出口网络",
        "label_en": "Exit network",
        "description_zh": "出口地址、运营商标签、跨站出口和双栈路径是否相互一致。",
        "description_en": "Whether the observed exit, provider labels, site routes, and dual-stack paths agree.",
        "patterns": ("network.egress.", "network.ip_reputation"),
    },
    {
        "id": "leak_detection",
        "label_zh": "泄漏检测",
        "label_en": "Leak detection",
        "description_zh": "DNS、IPv6、Teredo、WebRTC 等是否有已确认的旁路信号。",
        "description_en": "Whether DNS, IPv6, Teredo, or WebRTC checks show a confirmed side channel.",
        "patterns": (
            "network.dns",
            "network.dns_",
            "network.teredo",
            "network.ipv6_binding",
            "browser.webrtc.",
        ),
    },
    {
        "id": "regional_consistency",
        "label_zh": "区域一致性",
        "label_en": "Regional consistency",
        "description_zh": "系统语言、时区与在线出口区域标签是否互相矛盾。",
        "description_en": "Whether locale, timezone, and observed exit-region labels contradict one another.",
        "patterns": ("system.locale", "system.timezone", "consistency.geo_stack", "network.ip_reputation"),
    },
    {
        "id": "browser_identity",
        "label_zh": "浏览器身份",
        "label_en": "Browser identity",
        "description_zh": "当前审计不代替网页端 UA、Client Hints 或 HTTP 头实测；缺数据时保持未知。",
        "description_en": "The audit does not substitute for browser UA, Client Hints, or HTTP-header observation.",
        "patterns": ("browser.identity.",),
    },
    {
        "id": "device_fingerprint",
        "label_zh": "设备指纹",
        "label_en": "Device fingerprint",
        "description_zh": "只报告本地可见的浏览器/WebRTC 策略和 TLS 指纹，不做伪装。",
        "description_en": "Reports only locally visible browser/WebRTC policy and TLS observations; it does not spoof them.",
        "patterns": ("privacy.browser_fingerprint", "network.tls.fingerprint"),
    },
    {
        "id": "platform_reachability",
        "label_zh": "平台可达性",
        "label_en": "Platform reachability",
        "description_zh": "在线时观察 AI/服务主页是否可达；失败是未知，不是账号判决。",
        "description_en": "When online probing is enabled, observes reachability; failure is unknown, not an account verdict.",
        "patterns": ("network.ai_connectivity", "network.anthropic_baseurl_tcp"),
    },
)

_STATUS_LABELS = {
    "pass": ("通过", "Pass"),
    "warning": ("警告", "Warning"),
    "fail": ("未通过", "Fail"),
    "unknown": ("未知", "Unknown"),
}
_STATUS_RANK = {"fail": 0, "warning": 1, "unknown": 2, "pass": 3}


def _as_check_dict(check: Any) -> Dict[str, Any]:
    """Convert dataclass or mapping checks without retaining raw evidence."""

    if isinstance(check, Mapping):
        return dict(check)
    try:
        value = to_dict(check)
    except Exception:
        value = {}
    return value if isinstance(value, dict) else {}


def _status(value: Any) -> str:
    value = str(value or "unknown").strip().lower()
    return value if value in _STATUS_LABELS else "unknown"


def _confidence(value: Any) -> str:
    value = str(value or "unknown").strip().lower()
    return value if value in {"confirmed", "high", "probable", "possible", "low", "unknown"} else "unknown"


def _matches(check_id: str, patterns: Sequence[str]) -> bool:
    return any(check_id == pattern or check_id.startswith(pattern) for pattern in patterns)


def _aggregate_status(items: Sequence[Dict[str, Any]]) -> str:
    if not items:
        return "unknown"
    statuses = [_status(item.get("status")) for item in items]
    if "fail" in statuses:
        return "fail"
    if "warning" in statuses:
        return "warning"
    # A pass mixed with an unknown is still unknown.  This keeps the matrix
    # honest when only one side of a multi-signal check was observable.
    if all(status == "pass" for status in statuses):
        return "pass"
    return "unknown"


def _aggregate_confidence(items: Sequence[Dict[str, Any]], status: str) -> str:
    if not items or status == "unknown":
        return "unknown"
    if status in {"fail", "warning"}:
        # Confidence belongs to the signal driving the aggregate status. A
        # confirmed pass must not upgrade a separate probable warning.
        driving = [item for item in items if _status(item.get("status")) == status]
        values = [_confidence(item.get("confidence")) for item in driving]
        if "confirmed" in values or "high" in values:
            return "confirmed"
        return "probable" if any(value in {"probable", "possible"} for value in values) else "unknown"
    values = [_confidence(item.get("confidence")) for item in items]
    return "confirmed" if all(value in {"confirmed", "high"} for value in values) else "probable"


def build_dimension_matrix(checks: Iterable[Any]) -> Dict[str, Any]:
    """Return a redaction-safe six-dimension summary of *checks*.

    Only check ids, statuses, confidence, and short recommendations are
    retained.  Raw explanations/evidence (which may contain network values)
    stay in the normal report and are not copied into this matrix.
    """

    normalized = [_as_check_dict(check) for check in (checks or [])]
    normalized = [check for check in normalized if check.get("id")]
    dimensions: List[Dict[str, Any]] = []
    summary = {"pass": 0, "warning": 0, "fail": 0, "unknown": 0}
    for definition in DIMENSION_DEFINITIONS:
        matched = [
            check for check in normalized
            if _matches(str(check.get("id")), definition["patterns"])
        ]
        status = _aggregate_status(matched)
        confidence = _aggregate_confidence(matched, status)
        label_zh, label_en = _STATUS_LABELS[status]
        if matched:
            recommendation = next(
                (
                    str(check.get("recommendation") or "").strip()
                    for check in sorted(matched, key=lambda item: _STATUS_RANK[_status(item.get("status"))])
                    if str(check.get("recommendation") or "").strip()
                ),
                "",
            )
        else:
            recommendation = "本次没有覆盖这一维；保持“未知”，如需判断请主动开启对应的只读观测。"
        evidence = [
            {
                "id": str(check.get("id")),
                "status": _status(check.get("status")),
                "confidence": _confidence(check.get("confidence")),
            }
            for check in matched
        ]
        dimensions.append(
            {
                "id": definition["id"],
                "label_zh": definition["label_zh"],
                "label_en": definition["label_en"],
                "description_zh": definition["description_zh"],
                "description_en": definition["description_en"],
                "status": status,
                "status_label_zh": label_zh,
                "status_label_en": label_en,
                "confidence": confidence,
                "check_ids": [str(check.get("id")) for check in matched],
                "evidence": evidence,
                "matched": len(matched),
                "known": sum(_status(check.get("status")) != "unknown" for check in matched),
                "unknown": sum(_status(check.get("status")) == "unknown" for check in matched),
                "recommendation": recommendation,
            }
        )
        summary[status] += 1
    return {
        "version": "1.0",
        "score": None,
        "score_kind": "dimension_status_matrix",
        "score_note_zh": "六维状态矩阵不是新增评分，也不是 IP 纯净度或反封禁分。",
        "score_note_en": "This six-dimension matrix is not an IP purity, anti-ban, or risk score.",
        "dimensions": dimensions,
        "summary": summary,
    }


__all__ = ["DIMENSION_DEFINITIONS", "build_dimension_matrix"]
