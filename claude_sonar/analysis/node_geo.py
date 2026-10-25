"""Compare a proxy node display name with the observed egress country."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

from ..models import AuditCheck, Evidence

_CHINESE_TOKENS: Sequence[Tuple[str, str]] = (
    ("美国", "US"),
    ("洛杉矶", "US"),
    ("加州", "US"),
    ("日本", "JP"),
    ("东京", "JP"),
    ("大阪", "JP"),
    ("台湾", "TW"),
    ("香港", "HK"),
    ("新加坡", "SG"),
    ("韩国", "KR"),
    ("英国", "GB"),
    ("德国", "DE"),
    ("加拿大", "CA"),
    ("泰国", "TH"),
    ("越南", "VN"),
    ("菲律宾", "PH"),
    ("法国", "FR"),
    ("澳洲", "AU"),
    ("澳大利亚", "AU"),
)

_ENGLISH_PHRASES: Sequence[Tuple[str, str]] = (
    ("united states", "US"),
    ("los angeles", "US"),
    ("hong kong", "HK"),
    ("united kingdom", "GB"),
    ("frontier", "US"),
    ("at&t", "US"),
    ("japan", "JP"),
    ("tokyo", "JP"),
    ("taiwan", "TW"),
    ("singapore", "SG"),
    ("korea", "KR"),
    ("canada", "CA"),
    ("germany", "DE"),
    ("england", "GB"),
    ("britain", "GB"),
    ("australia", "AU"),
    ("thailand", "TH"),
    ("vietnam", "VN"),
    ("philippines", "PH"),
)

_SHORT_CODES: Sequence[Tuple[str, str]] = (
    ("usa", "US"),
    ("us", "US"),
    ("jp", "JP"),
    ("tw", "TW"),
    ("hk", "HK"),
    ("sg", "SG"),
    ("kr", "KR"),
    ("gb", "GB"),
    ("uk", "GB"),
    ("de", "DE"),
    ("ca", "CA"),
    ("au", "AU"),
    ("th", "TH"),
    ("vn", "VN"),
    ("ph", "PH"),
    ("fr", "FR"),
)


def named_region_codes(node_name: Any) -> frozenset:
    text = str(node_name or "")
    if not text.strip():
        return frozenset()
    lower = text.lower()
    found = set()
    for token, code in _CHINESE_TOKENS:
        if token in text:
            found.add(code)
    for token, code in _ENGLISH_PHRASES:
        if token in lower:
            found.add(code)
    for token, code in _SHORT_CODES:
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lower):
            found.add(code)
    return frozenset(found)


def evaluate_node_geo(node_name: Any, observed_country: Any) -> Tuple[str, str]:
    name = str(node_name or "").strip()
    named = named_region_codes(name)
    observed = str(observed_country or "").strip().upper()
    if observed and len(observed) != 2:
        observed = ""
    if not name:
        return "unknown", "没有选中的节点名，无法对照出口国家。"
    if not named:
        return "unknown", f"节点名没有可识别的地区词：{name}。"
    named_text = "/".join(sorted(named))
    if not observed:
        return "unknown", f"节点名指向 {named_text}，但还没有观测到出口国家。"
    if observed in named:
        return "pass", f"节点名地区 {named_text} 与出口国家 {observed} 一致。"
    return (
        "warning",
        f"节点名指向 {named_text}，实际出口国家是 {observed}。名字和真实出口不是同一个地方。",
    )


def _reputation_country(checks: Iterable[Any]) -> Optional[str]:
    for check in checks or []:
        check_id = getattr(check, "id", None) or (check.get("id") if isinstance(check, dict) else None)
        if check_id not in (
            "network.ip_reputation",
            "network.egress.reputation",
            "network.egress.ip_reputation",
        ):
            continue
        evidence_list = getattr(check, "evidence", None)
        if evidence_list is None and isinstance(check, dict):
            evidence_list = check.get("evidence") or []
        for item in evidence_list or []:
            data = getattr(item, "data", None)
            if data is None and isinstance(item, dict):
                data = item.get("data")
            if not isinstance(data, dict):
                continue
            for key in ("country_code", "country", "Country", "CountryCode"):
                raw = data.get(key)
                if raw is None:
                    continue
                text = str(raw).strip().upper()
                if len(text) == 2 and text.isalpha():
                    return text
    return None


def merge_node_geo_with_egress(checks):
    """Fill network.node_geo once an online reputation country is known."""
    if not checks:
        return checks
    country = _reputation_country(checks)
    if not country:
        return checks
    for check in checks:
        check_id = getattr(check, "id", None) or (check.get("id") if isinstance(check, dict) else None)
        if check_id != "network.node_geo":
            continue
        evidence_list = getattr(check, "evidence", None)
        if evidence_list is None and isinstance(check, dict):
            evidence_list = check.get("evidence") or []
        node_name = ""
        for item in evidence_list or []:
            data = getattr(item, "data", None)
            if data is None and isinstance(item, dict):
                data = item.get("data")
            if isinstance(data, dict) and data.get("node_name"):
                node_name = str(data.get("node_name") or "")
                break
        if not node_name:
            continue
        status, explanation = evaluate_node_geo(node_name, country)
        if hasattr(check, "status"):
            check.status = status
            check.explanation = explanation
            check.severity = "low" if status == "warning" else "info"
            check.confidence = "probable" if status == "warning" else (
                "confirmed" if status == "pass" else "unknown"
            )
        elif isinstance(check, dict):
            check["status"] = status
            check["explanation"] = explanation
        break
    return checks


def collect_node_geo_check(builder, leaf: Optional[Mapping[str, Any]], observed_country: Any = None) -> None:
    name = str((leaf or {}).get("Name") or "").strip()
    status, explanation = evaluate_node_geo(name, observed_country)
    builder.add(
        "network.node_geo",
        "Node name vs egress country",
        "network",
        status,
        "low" if status == "warning" else "info",
        explanation,
        "节点名和出口国家不一致时，换一条名字与出口相符的节点，或接受名字只是商家标签。",
        evidence=[Evidence(
            type="policy_leaf",
            description="selected node name",
            data={"node_name": name, "named_regions": sorted(named_region_codes(name))},
        )],
    )
