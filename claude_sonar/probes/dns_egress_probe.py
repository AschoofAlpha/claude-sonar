"""DNS egress vs HTTP egress consistency (DoH-based, read-only observation).

Absorbs the "DoH exit IP" idea from newtv-ai/CLAUDE-SHIELD but keeps this
project's privacy rules:

- Only well-known public names are queried (``o-o.myaddr.l.google.com`` TXT
  via Google DoH). No unique/random labels under public suffixes.
- The DoH exit token is compared against the HTTP egress token from the
  existing :func:`claude_sonar.probes.egress.observe_egress_url` logic.
- Raw addresses are never persisted: both sides are pseudonymized with the
  same in-memory :class:`Redactor` salt before comparison.
- DoH unreachable is ``unknown``, never a failure — proxies often block
  dns.google; that is not proof of a leak.

A mismatch is a *possible* DNS leak / split-routing hint, reported as a
neutral warning. This module never changes DNS, routes, or system settings.
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.request
from typing import Any, Dict, Optional, Sequence

from ..models import AuditCheck, Evidence
from ..redaction import Redactor
from .egress import extract_ip, observe_egress_url

# Public echo name with a stable TXT answer; no unique labels.
_DOH_URL = "https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT"
_HTTP_EGRESS_URL = "https://api.ipify.org"


def fetch_doh_exit_ip(timeout: int = 5) -> Optional[str]:
    """Return the exit IP observed by Google DoH, or None when unreachable.

    Parses the JSON DNS response for the TXT answer of
    ``o-o.myaddr.l.google.com`` (e.g. ``"edns0-client-subnet 203.0.113.0/32"``
    or a bare address). Callers must redact before persisting.
    """
    try:
        req = urllib.request.Request(
            _DOH_URL,
            headers={"Accept": "application/dns-json"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            payload = resp.read(16384)
        data = json.loads(payload.decode("utf-8", errors="ignore"))
        for answer in data.get("Answer", []) or []:
            if str(answer.get("type")) == "16":  # TXT
                txt = "".join(answer.get("data", "") or "")
                ip = extract_ip(txt)
                if ip:
                    return ip.split("/", 1)[0].strip()
        return None
    except Exception:
        return None


def _redact_token(ip_str: Optional[str], redactor: Redactor) -> Optional[str]:
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    if ip.version == 6:
        return redactor.redact_ipv6(str(ip))
    return redactor.redact_ipv4(str(ip))


def check_dns_egress_consistency(
    timeout: int = 5,
    *,
    redactor: Optional[Redactor] = None,
    existing_checks: Optional[Sequence[Any]] = None,
) -> AuditCheck:
    """Compare DoH-resolved exit with HTTP egress; read-only observation."""
    # fake-IP + port-53 hijacking already routes DNS through the tunnel:
    # the DoH comparison adds nothing and dns.google is commonly blocked.
    if existing_checks:
        by_id = {}
        for check in existing_checks:
            cid = getattr(check, "id", None)
            if cid:
                by_id[cid] = check
        fakeip = by_id.get("network.dns_mode")
        hijack = by_id.get("network.dns_hijack")
        def _st(check):
            return str(getattr(check, "status", "") or "").lower()
        if (
            fakeip is not None and _st(fakeip) == "pass"
            and "fake-ip" in str(getattr(fakeip, "explanation", "") or "").lower()
            and hijack is not None and _st(hijack) == "pass"
        ):
            return AuditCheck(
                id="network.dns.egress_consistency",
                title="DNS egress consistency (DoH vs HTTP, read-only)",
                category="network",
                status="pass",
                severity="info",
                confidence="confirmed",
                evidence=[Evidence(
                    type="dns_egress_consistency",
                    description="DNS routed via fake-IP + port-53 hijacking (DoH comparison skipped)",
                    data={"skipped_reason": "fakeip_and_hijack", "raw_value_persisted": False},
                )],
                explanation=(
                    "fake-IP 与 53 端口劫持已开启，DNS 查询走代理隧道；"
                    "跳过 DoH 对照（dns.google 常被代理拦截，不影响结论）。"
                ),
            )

    redactor = redactor or Redactor()
    per = max(1, min(int(timeout) or 1, 5))

    doh_ip = fetch_doh_exit_ip(per)
    http_obs: Dict[str, Any] = observe_egress_url(
        _HTTP_EGRESS_URL, timeout=per, redactor=redactor
    )

    doh_token = _redact_token(doh_ip, redactor)
    http_token = http_obs.get("observed_address") if http_obs.get("ok") else None

    evidence_data: Dict[str, Any] = {
        "doh": {
            "ok": bool(doh_token),
            "observed_address": doh_token,
            "doh_endpoint": "dns.google",
            "query_name": "o-o.myaddr.l.google.com",
            "unique_label_technique": "not_used",
            "raw_value_persisted": False,
        },
        "http": {
            "ok": bool(http_token),
            "observed_address": http_token,
            "raw_value_persisted": False,
        },
        "match": None,
        "raw_value_persisted": False,
    }
    evidence = [Evidence(
        type="dns_egress_consistency",
        description="DNS (DoH) exit vs HTTP egress observation (redacted tokens only)",
        data=evidence_data,
    )]

    if doh_token and http_token:
        match = doh_token == http_token
        evidence_data["match"] = match
        if match:
            return AuditCheck(
                id="network.dns.egress_consistency",
                title="DNS egress consistency (DoH vs HTTP, read-only)",
                category="network",
                status="pass",
                severity="info",
                confidence="confirmed",
                evidence=evidence,
                explanation=(
                    "只读检测：DNS 解析出口与 HTTP 出口一致（同一脱敏 token）。"
                    "DoH 与 HTTP 走了同一出口路径，未观察到 DNS 分流迹象。"
                ),
            )
        return AuditCheck(
            id="network.dns.egress_consistency",
            title="DNS egress consistency (DoH vs HTTP, read-only)",
            category="network",
            status="warning",
            severity="low",
            confidence="possible",
            evidence=evidence,
            explanation=(
                "只读检测：DNS 解析出口与 HTTP 出口不同"
                f"（DNS 出口 token {doh_token}，HTTP 出口 token {http_token}），"
                "可能 DNS 泄漏或分流。这是观察结果而非定论；"
                "也可能是出口多 IP 轮换造成的正常差异。本工具不会自动修改任何设置。"
            ),
            recommendation=(
                "若确认是 DNS 分流：让 Claude Code 走 socks5h:// 形式的代理"
                "（如 socks5h://127.0.0.1:7891），域名解析会交给代理远程完成，"
                "减少本地 DNS 绕过。此为建议，是否修改由你决定。"
            ),
        )

    if not doh_token:
        evidence_data["match"] = None
        return AuditCheck(
            id="network.dns.egress_consistency",
            title="DNS egress consistency (DoH vs HTTP, read-only)",
            category="network",
            status="unknown",
            severity="info",
            confidence="unknown",
            evidence=evidence,
            explanation=(
                "[doh_unavailable] DoH 查询不可达，无法对比 DNS 解析出口"
                "（代理策略常拦截 dns.google，这本身不等于 DNS 泄漏）。"
                "本次只读检测未得出对比结果。"
            ),
            recommendation=(
                "可选：让 Claude Code 走 socks5h:// 形式的代理"
                "（域名解析交给代理远程完成），从机制上减少 DNS 绕过。"
                "此为建议，是否修改由你决定。"
            ),
        )

    return AuditCheck(
        id="network.dns.egress_consistency",
        title="DNS egress consistency (DoH vs HTTP, read-only)",
        category="network",
        status="unknown",
        severity="info",
        confidence="unknown",
        evidence=evidence,
        explanation=(
            "[http_egress_unavailable] HTTP 出口探测不可达，无法对比 DNS 解析出口。"
            "本次只读检测未得出对比结果。"
        ),
    )
