"""Cross-site egress routing observation (online only).

Fetches a small set of public observation URLs and compares redacted egress
tokens. Same redactor instance is used so equal IPs map to equal tokens.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from ..models import AuditCheck, Evidence
from ..redaction import Redactor
from .base import ProbeError
from .egress import extract_ip
from .http_probe import fetch_http
from .safety import validate_url

# Small default set — two independent public observers.
DEFAULT_CROSS_SITE_URLS: Sequence[str] = (
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ipify.org",
)


def _site_label(url: str) -> str:
    host = urlparse(url).hostname or "unknown"
    return host.lower()


def _redact_token(redactor: Redactor, ip_str: str) -> Optional[dict]:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    if ip.version == 6:
        token = redactor.redact_ipv6(str(ip))
        family = "ipv6"
    else:
        token = redactor.redact_ipv4(str(ip))
        family = "ipv4"
    return {
        "observed_address": token,
        "address_family": family,
        "raw_value_persisted": False,
    }


def check_cross_site_routing(
    urls: Optional[Iterable[str]] = None,
    timeout: int = 5,
    redactor: Optional[Redactor] = None,
    observations: Optional[Iterable[dict]] = None,
) -> AuditCheck:
    """Compare observed egress tokens across sites.

    - match  => pass
    - mismatch => warning
    - failures / insufficient samples => unknown

    ``observations`` lets callers hand in already-collected redacted tokens
    (e.g. from the same-run egress checks) so the probe does not re-fetch.
    """
    redactor = redactor or Redactor()
    if observations is not None:
        obs_list = [
            item for item in observations
            if isinstance(item, dict) and item.get("observed_address")
        ]
        tokens = [str(item.get("observed_address")) for item in obs_list]
        evidence = [Evidence(
            type="cross_site_routing",
            description="Redacted egress tokens per site (reused from run)",
            data={"sites": obs_list, "raw_value_persisted": False},
        )]
        if len(tokens) < 2:
            return AuditCheck(
                id="network.cross_site.routing",
                title="Cross-site egress routing",
                category="network",
                status="unknown",
                severity="info",
                confidence="unknown",
                evidence=evidence,
                explanation="可用的出口样本不足两个，证据不够，不算泄漏也不算通过。",
            )
        if len(set(tokens)) == 1:
            return AuditCheck(
                id="network.cross_site.routing",
                title="Cross-site egress routing",
                category="network",
                status="pass",
                severity="info",
                confidence="confirmed",
                evidence=evidence,
                explanation=(
                    f"{len(tokens)} 个观测站点的出口 token 一致；"
                    "测试集合的出口路径一致。"
                ),
            )
        return AuditCheck(
            id="network.cross_site.routing",
            title="Cross-site egress routing",
            category="network",
            status="warning",
            severity="medium",
            confidence="possible",
            evidence=evidence,
            explanation=(
                f"观测站点的出口 token 不一致（{len(set(tokens))} 种），"
                "可能分流或负载均衡——不是账户风险证明。"
            ),
        )

    url_list: List[str] = list(urls) if urls is not None else list(DEFAULT_CROSS_SITE_URLS)
    if not url_list:
        url_list = list(DEFAULT_CROSS_SITE_URLS)

    observations = []
    failures = []

    for url in url_list:
        label = _site_label(url)
        try:
            validate_url(url)
            body, ssrf_mode = fetch_http(url, timeout=timeout, max_bytes=16384)
            ip_str = extract_ip(body or "")
            if not ip_str:
                failures.append({"site": label, "error": "no_ip_extracted"})
                continue
            token = _redact_token(redactor, ip_str)
            if not token:
                failures.append({"site": label, "error": "invalid_ip"})
                continue
            observations.append({
                "site": label,
                "ssrf_validation_mode": ssrf_mode,
                **token,
            })
        except ProbeError as exc:
            failures.append({"site": label, "error": type(exc).__name__})
        except Exception as exc:  # noqa: BLE001 — best-effort
            failures.append({"site": label, "error": type(exc).__name__})

    evidence = []
    if observations:
        evidence.append(Evidence(
            type="cross_site_routing",
            description="Redacted egress tokens per site",
            data={
                "sites": observations,
                "raw_value_persisted": False,
            },
        ))
    if failures:
        evidence.append(Evidence(
            type="cross_site_routing_failure",
            description="Sites that could not be observed",
            data={"failures": failures, "raw_value_persisted": False},
        ))

    tokens = [o["observed_address"] for o in observations if o.get("observed_address")]

    if len(tokens) < 2:
        return AuditCheck(
            id="network.cross_site.routing",
            title="Cross-site egress routing",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation="可用的出口样本不足两个，证据不够，不算泄漏也不算通过。",
        )

    unique = set(tokens)
    if len(unique) == 1:
        return AuditCheck(
            id="network.cross_site.routing",
            title="Cross-site egress routing",
            category="network",
            status="pass",
            severity="info",
            confidence="confirmed",
            evidence=evidence,
            explanation=(
                f"Egress tokens match across {len(tokens)} observed sites "
                f"(token {tokens[0]}). Same exit path is consistent for the tested set."
            ),
        )

    return AuditCheck(
        id="network.cross_site.routing",
        title="Cross-site egress routing",
        category="network",
        status="warning",
        severity="medium",
        confidence="possible",
        evidence=evidence,
        explanation=(
            f"Egress tokens differ across observed sites ({len(unique)} distinct tokens "
            f"over {len(tokens)} successes). This may indicate split routing, "
            "load balancing, or unintended direct egress — not proof of account risk."
        ),
    )
