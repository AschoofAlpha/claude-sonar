"""Compare egress tokens across Anthropic web properties (online)."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from ..models import AuditCheck, Evidence
from ..redaction import Redactor
from .base import ProbeError
from .egress import extract_ip
from .http_probe import fetch_http
from .safety import validate_url

DEFAULT_ANTHROPIC_TRACE_URLS: Sequence[str] = (
    "https://claude.ai/cdn-cgi/trace",
    "https://claude.com/cdn-cgi/trace",
    "https://www.anthropic.com/cdn-cgi/trace",
)


def _site_label(url: str) -> str:
    host = urlparse(url).hostname or "unknown"
    return host.lower()


def check_anthropic_split(
    observations: Optional[Iterable[dict]] = None,
    timeout: int = 5,
    redactor: Optional[Redactor] = None,
    urls: Optional[Iterable[str]] = None,
) -> AuditCheck:
    """Fail when Anthropic hostnames exit via different redacted tokens."""
    redactor = redactor or Redactor()
    obs_list: List[dict]
    if observations is not None:
        obs_list = [
            item for item in observations
            if isinstance(item, dict) and item.get("observed_address")
        ]
    else:
        obs_list = []
        url_list = list(urls) if urls is not None else list(DEFAULT_ANTHROPIC_TRACE_URLS)
        for url in url_list:
            label = _site_label(url)
            try:
                validate_url(url)
                body, _ssrf = fetch_http(url, timeout=timeout, max_bytes=16384)
                ip_str = extract_ip(body or "")
                if not ip_str:
                    continue
                token = redactor.redact_ipv4(ip_str) if ":" not in ip_str else redactor.redact_ipv6(ip_str)
                obs_list.append({"site": label, "observed_address": token})
            except (ProbeError, Exception):
                continue

    evidence = [Evidence(
        type="anthropic_split",
        description="Redacted egress tokens for Anthropic hostnames",
        data={"sites": [{"site": o.get("site"), "observed_address": o.get("observed_address")} for o in obs_list],
              "raw_value_persisted": False},
    )]
    tokens = [str(item.get("observed_address")) for item in obs_list if item.get("observed_address")]
    if len(tokens) < 2:
        return AuditCheck(
            id="network.anthropic_split",
            title="Anthropic hostname egress split",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation="Anthropic 域名出口样本不足两个，证据不够。",
        )
    unique = {}
    for item in obs_list:
        unique.setdefault(str(item.get("observed_address")), []).append(str(item.get("site") or ""))
    if len(unique) == 1:
        return AuditCheck(
            id="network.anthropic_split",
            title="Anthropic hostname egress split",
            category="network",
            status="pass",
            severity="info",
            confidence="confirmed",
            evidence=evidence,
            explanation=f"{len(tokens)} 个 Anthropic 域名出口 token 一致。",
        )
    groups = "；".join(
        f"{token}→{', '.join(sorted(set(sites)))}" for token, sites in unique.items()
    )
    return AuditCheck(
        id="network.anthropic_split",
        title="Anthropic hostname egress split",
        category="network",
        status="fail",
        severity="medium",
        confidence="confirmed",
        evidence=evidence,
        explanation=(
            f"Anthropic 域名走了不同出口：{groups}。"
            "规则集需要同时覆盖 claude.ai / claude.com / anthropic.com。"
        ),
        recommendation="给 claude.com、claudeusercontent.com、claude.site、anthropic.com 配同一条策略组。",
    )
