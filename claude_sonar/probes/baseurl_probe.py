"""ANTHROPIC_BASE_URL audit against a bundled public relay-risk blacklist.

Read-only environment inspection; no network contact. The blacklist is
third-party risk intelligence (CACEB001/Claude-Shield, ``main`` branch) that
is shipped as plain data in
``claude_sonar/resources/known_baseurl_blacklist.txt``. The upstream data is
stored upstream as a base64 + XOR-91 blob; :func:`decode_xor91_blob` implements
that public decoding step in pure Python for reproducibility and testing.

Tone contract: this check *hints at risk*. A custom relay endpoint is a
warning, and a relay that appears in the public blacklist is a high warning.
It is never an accusation and never a bypass mechanism — the tool does not
help "launder" or hide an endpoint, and the report wording stays neutral.
"""

from __future__ import annotations

import base64
import os
import socket
import urllib.parse
from typing import List, Optional

from ..models import AuditCheck, Evidence
from ..resources import resource_path

_OFFICIAL_HOSTS = frozenset({"api.anthropic.com"})
_BLACKLIST_SOURCE = "CACEB001/Claude-Shield main (147 entries, base64+XOR91 decoded)"
_LABWORDS_SOURCE = "CACEB001/Claude-Shield main (LAB_BLOB, base64+XOR91 decoded)"
_FALLBACK_SOURCE = "fallback common relay patterns (bundled blacklist data missing)"
_FALLBACK_PATTERNS = (
    "workers.dev",
    "zeabur.app",
    "fcapp.run",
    "vercel.app",
    "railway.app",
    "glitch.me",
    "netlify.app",
    "deno.dev",
    "pages.dev",
    "onrender.com",
)

# Kept identical to the generator (scripts/gen_baseurl_blacklist.py) so the
# bundled data stays reproducible.
XOR_KEY = 91


def decode_xor91_blob(encoded: str, xor_key: int = XOR_KEY) -> List[str]:
    """Decode a base64 + XOR blob into a comma-separated domain list.

    Public algorithm used by the upstream intelligence source: base64-decode,
    XOR every byte with ``xor_key`` (91), split on commas, trim, drop
    empties. Pure function — easy to verify with a fixed sample.
    """
    raw = base64.b64decode(encoded.strip())
    text = bytes(b ^ xor_key for b in raw).decode("utf-8", errors="replace")
    return [item.strip() for item in text.split(",") if item.strip()]


def load_blacklist() -> List[str]:
    """Load bundled blacklist entries (one domain per line, lowercase).

    If the bundled data file is missing or unreadable (e.g. a stripped
    installation), degrade to a short list of common relay platform patterns
    and remember that the source is missing (returned via the optional
    ``source`` companion function).
    """
    try:
        path = resource_path("claude_sonar", "resources", "known_baseurl_blacklist.txt")
        entries = [
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if entries:
            return entries
    except Exception:  # pragma: no cover - degraded install
        pass
    return list(_FALLBACK_PATTERNS)


def blacklist_source() -> str:
    """Human-readable provenance of the loaded blacklist."""
    try:
        resource_path("claude_sonar", "resources", "known_baseurl_blacklist.txt")
        return _BLACKLIST_SOURCE
    except Exception:  # pragma: no cover - degraded install
        return _FALLBACK_SOURCE


def _matches(host: str, entry: str) -> bool:
    """Suffix match: ``api.wolfai.top`` matches entry ``wolfai.top``."""
    return host == entry or host.endswith("." + entry)


def find_blacklist_hit(host: str, entries: Optional[List[str]] = None) -> Optional[str]:
    entries = list(entries) if entries is not None else load_blacklist()
    for entry in entries:
        if _matches(host, entry):
            return entry
    return None


def load_labwords() -> List[str]:
    """Load bundled AI-lab keyword entries (one word per line, lowercase).

    Degrades to an empty list when the data file is missing (a stripped
    install): the keyword check then simply reports no hit.
    """
    try:
        path = resource_path("claude_sonar", "resources", "known_baseurl_labwords.txt")
        words = [
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if words:
            return words
    except Exception:  # pragma: no cover - degraded install
        pass
    return []


def labwords_source() -> str:
    """Human-readable provenance of the loaded lab-keyword list."""
    try:
        resource_path("claude_sonar", "resources", "known_baseurl_labwords.txt")
        return _LABWORDS_SOURCE
    except Exception:  # pragma: no cover - degraded install
        return _FALLBACK_SOURCE


def find_labword_hit(host: str, words: Optional[List[str]] = None) -> Optional[str]:
    """Substring hit: ``api.deepseek-relay.com`` matches keyword ``deepseek``."""
    words = list(words) if words is not None else load_labwords()
    lowered = host.lower()
    for word in words:
        if word and word in lowered:
            return word
    return None


def check_anthropic_baseurl() -> AuditCheck:
    """Audit ANTHROPIC_BASE_URL: unset / official / custom / blacklisted."""
    raw = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    evidence_data = {
        "base_url_set": bool(raw),
        "host_class": "unset",
        "blacklist_hit": False,
        "blacklist_source": blacklist_source(),
        "labword_hit": False,
        "labword_source": labwords_source(),
        "raw_value_persisted": False,
    }

    if not raw:
        evidence_data["host_class"] = "unset"
        return AuditCheck(
            id="network.anthropic_baseurl",
            title="ANTHROPIC_BASE_URL audit",
            category="network",
            status="pass",
            severity="info",
            confidence="confirmed",
            evidence=[Evidence(
                type="env_baseurl",
                description="ANTHROPIC_BASE_URL environment observation (host class only)",
                data=evidence_data,
            )],
            explanation=(
                "[not_configured] 未检测到 ANTHROPIC_BASE_URL 环境变量："
                "Claude 默认连接官方端点 api.anthropic.com。"
            ),
        )

    host: Optional[str] = None
    try:
        parsed = urllib.parse.urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").lower()
    except Exception:
        host = None

    if not host:
        evidence_data["host_class"] = "unparseable"
        return AuditCheck(
            id="network.anthropic_baseurl",
            title="ANTHROPIC_BASE_URL audit",
            category="network",
            status="warning",
            severity="low",
            confidence="probable",
            evidence=[Evidence(
                type="env_baseurl",
                description="ANTHROPIC_BASE_URL environment observation (host class only)",
                data=evidence_data,
            )],
            explanation=(
                "ANTHROPIC_BASE_URL 已设置但无法解析出有效域名（原始值不落盘）。"
                "请检查该变量是否为完整 URL，例如 https://api.anthropic.com。"
            ),
        )

    evidence_data["host_class"] = "official" if host in _OFFICIAL_HOSTS else "custom"
    evidence_data["hostname"] = host

    if host in _OFFICIAL_HOSTS:
        return AuditCheck(
            id="network.anthropic_baseurl",
            title="ANTHROPIC_BASE_URL audit",
            category="network",
            status="pass",
            severity="info",
            confidence="confirmed",
            evidence=[Evidence(
                type="env_baseurl",
                description="ANTHROPIC_BASE_URL environment observation (host class only)",
                data=evidence_data,
            )],
            explanation="ANTHROPIC_BASE_URL 指向官方端点 api.anthropic.com。",
        )

    hit = find_blacklist_hit(host)
    evidence_data["blacklist_hit"] = bool(hit)
    if hit:
        evidence_data["blacklist_entry"] = hit
        return AuditCheck(
            id="network.anthropic_baseurl",
            title="ANTHROPIC_BASE_URL audit",
            category="network",
            status="warning",
            severity="high",
            confidence="confirmed",
            evidence=[Evidence(
                type="env_baseurl",
                description="ANTHROPIC_BASE_URL vs public relay-risk blacklist (risk intel)",
                data=evidence_data,
            )],
            explanation=(
                f"ANTHROPIC_BASE_URL 指向的中转域名 {host} 出现在公开风控黑名单情报中"
                f"（命中 {hit}；来源：{evidence_data['blacklist_source']}）。"
                "这是第三方风险提示情报，不代表账号已受影响；是否继续使用由你决定。"
            ),
        )

    lab_hit = find_labword_hit(host)
    evidence_data["labword_hit"] = bool(lab_hit)
    if lab_hit:
        evidence_data["labword_entry"] = lab_hit
        return AuditCheck(
            id="network.anthropic_baseurl",
            title="ANTHROPIC_BASE_URL audit",
            category="network",
            status="warning",
            severity="low",
            confidence="possible",
            evidence=[Evidence(
                type="env_baseurl",
                description="ANTHROPIC_BASE_URL vs AI-lab keyword list (risk intel, substring heuristic)",
                data=evidence_data,
            )],
            explanation=(
                f"ANTHROPIC_BASE_URL 指向的中转域名 {host} 包含 AI 实验室相关关键词"
                f"（{lab_hit}；来源：{evidence_data.get('labword_source', labwords_source())}）。"
                "此类域名可能更容易被风控关注；这是子串启发的风险提示，不是判决，"
                "本工具不提供任何绕过手段。"
            ),
        )

    return AuditCheck(
        id="network.anthropic_baseurl",
        title="ANTHROPIC_BASE_URL audit",
        category="network",
        status="warning",
        severity="low",
        confidence="probable",
        evidence=[Evidence(
            type="env_baseurl",
            description="ANTHROPIC_BASE_URL environment observation (host class only)",
            data=evidence_data,
        )],
        explanation=(
            f"ANTHROPIC_BASE_URL 指向第三方中转端点 {host}：自定义中转存在风控风险"
            "（风险提示，不是判决；本工具不提供任何绕过手段）。"
        ),
    )


def _tcp_connect(host: str, port: int, timeout: int) -> bool:
    """Best-effort TCP connect. Module-level so tests can monkeypatch it."""
    with socket.create_connection((host, port), timeout=timeout):
        return True


def check_anthropic_baseurl_tcp(timeout: int = 5) -> AuditCheck:
    """Live TCP reachability of the configured ANTHROPIC_BASE_URL (--online).

    Read-only: opens a plain TCP connection to the configured host's 443 port
    and closes it. No HTTP request, no credentials, nothing persisted. The
    raw value is never stored. Note this is a direct dial that does not go
    through a local proxy — it answers "is the relay host itself alive", not
    "can Claude Code reach it through my proxy".
    """
    base_kwargs = dict(
        id="network.anthropic_baseurl_tcp",
        title="ANTHROPIC_BASE_URL TCP reachability (read-only)",
        category="network",
    )
    raw = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if not raw:
        return AuditCheck(
            status="pass",
            severity="info",
            confidence="confirmed",
            explanation=(
                "[not_configured] 未设置 ANTHROPIC_BASE_URL，"
                "无需定点连通测试（默认连接官方端点）。"
            ),
            **base_kwargs,
        )
    try:
        host = (urllib.parse.urlparse(
            raw if "://" in raw else f"https://{raw}"
        ).hostname or "").lower()
    except Exception:
        host = ""
    if not host:
        return AuditCheck(
            status="unknown",
            severity="info",
            confidence="unknown",
            explanation="[unparseable] ANTHROPIC_BASE_URL 无法解析出域名，跳过连通测试。",
            **base_kwargs,
        )
    per = max(1, min(int(timeout) or 3, 10))
    try:
        reachable = _tcp_connect(host, 443, per)
    except Exception:
        reachable = False
    if reachable:
        return AuditCheck(
            status="pass",
            severity="info",
            confidence="confirmed",
            evidence=[Evidence(
                type="baseurl_tcp",
                description="TCP 443 connect result (host only; raw value not persisted)",
                data={"host": host, "port": 443, "reachable": True,
                      "raw_value_persisted": False},
            )],
            explanation=(
                f"直连 TCP 探测：{host}:443 可连通（中转服务器本身存活）。"
                "该探测不经过本地代理，不代表 Claude Code 走代理时的可达性。"
            ),
            **base_kwargs,
        )
    return AuditCheck(
        status="warning",
        severity="low",
        confidence="possible",
        evidence=[Evidence(
            type="baseurl_tcp",
            description="TCP 443 connect result (host only; raw value not persisted)",
            data={"host": host, "port": 443, "reachable": False,
                  "raw_value_persisted": False},
        )],
        explanation=(
            f"直连 TCP 探测：{host}:443 无法连通。中转服务器可能已下线、被墙，"
            "或只允许走代理访问（本探测为直连，不经过本地代理）。"
            "建议用你实际使用的代理路径验证。"
        ),
        **base_kwargs,
    )
