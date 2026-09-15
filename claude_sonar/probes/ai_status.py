"""AI-platform connectivity observation (online only, reachability only).

Fetches a fixed list of AI platform homepages through the same proxy-aware
HTTP path as the other online probes and records per-platform reachability.
No credentials, no IP extraction, no verdict — a failed platform is reported
as unknown, never as a leak or an account-risk claim.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from ..models import AuditCheck, Evidence
from .base import ProbeError
from .http_probe import fetch_http

# (platform label, homepage). Reachability only — the response body is never
# parsed for identifiers. Homepages are fetched, not API endpoints, so no
# account or credential surface is touched.
DEFAULT_AI_PLATFORM_URLS: Sequence[Tuple[str, str]] = (
    ("ChatGPT", "https://chatgpt.com/"),
    ("Claude (claude.ai)", "https://claude.ai/"),
    ("Claude (claude.com)", "https://claude.com/"),
    ("Grok", "https://grok.com/"),
    ("Perplexity", "https://www.perplexity.ai/"),
    ("Gemini", "https://gemini.google.com/"),
    ("DeepSeek", "https://chat.deepseek.com/"),
    ("通义千问", "https://tongyi.aliyun.com/"),
    ("Kimi", "https://www.kimi.com/"),
)

_original_fetch_http = fetch_http


def check_ai_connectivity(
    timeout: int = 5,
    urls: Optional[Iterable[Tuple[str, str]]] = None,
) -> AuditCheck:
    """Observe per-platform reachability from this machine's HTTP path.

    - all reachable          => pass
    - any failure (incl. all) => unknown (connectivity failure is not a leak)

    The fetch follows the same proxy-aware path as the cross-site probes, so
    "reachable" means reachable through the user's current proxy posture.
    """
    base_kwargs = dict(
        id="network.ai_connectivity",
        title="AI platform connectivity (read-only)",
        category="network",
    )
    targets: List[Tuple[str, str]] = (
        list(urls) if urls is not None else list(DEFAULT_AI_PLATFORM_URLS)
    )
    if not targets:
        targets = list(DEFAULT_AI_PLATFORM_URLS)

    per = max(1, min(int(timeout) or 5, 10))
    platforms = []
    failures = []

    for platform, url in targets:
        try:
            fetch_http(url, timeout=per, max_bytes=4096)
            platforms.append({"platform": platform, "reachable": True})
        except ProbeError as exc:
            platforms.append({"platform": platform, "reachable": False, "error": type(exc).__name__})
            failures.append(platform)
        except Exception as exc:  # noqa: BLE001 — best-effort observation
            platforms.append({"platform": platform, "reachable": False, "error": type(exc).__name__})
            failures.append(platform)

    evidence = [Evidence(
        type="ai_connectivity",
        description="Per-platform reachability via the current HTTP path (no credentials, no identifiers)",
        data={"platforms": platforms, "raw_value_persisted": False},
    )]

    if failures:
        return AuditCheck(
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation=(
                f"{len(platforms) - len(failures)}/{len(platforms)} 个平台可达；"
                f"以下平台本次不可达：{', '.join(failures)}。"
                "连通性失败可能是地区限制、平台风控或临时故障，"
                "不代表本机配置泄漏，也不构成账号风险判决。"
            ),
            **base_kwargs,
        )

    return AuditCheck(
        status="pass",
        severity="info",
        confidence="confirmed",
        evidence=evidence,
        explanation=(
            f"{len(platforms)} 个 AI 平台主页本次全部可达（沿当前代理路径）。"
            "这只是连通性观察，不涉及账号状态判断。"
        ),
        **base_kwargs,
    )
