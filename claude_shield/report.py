"""Markdown report formatter and three-tier action classification.

Maps AuditCheck rows into Must fix / Optional consistency / Leave alone
per SKILL.md Report Format. Adds plain-language explanations so non-experts
can read jargon without losing technical IDs.

Pure presentation — no collector I/O.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# Checks that indicate routing/DNS leak risk when not passing.
_LEAKISH_IDS = frozenset({
    "network.allow_lan",
    "network.dns",
    "network.dns_mode",
    "network.dns_hijack",
    "network.strict_route",
    "network.dns_physical_resolver",
    "network.teredo",
    "network.ipv6_binding",
    "network.dns_respect_rules",
})

# Non-leak consistency / preference signals.
_OPTIONAL_IDS = frozenset({
    "system.locale",
    "system.timezone",
    "network.tun",
    "network.tun_stack",
    "network.env_proxy",
    "network.dns_ipv6",
    "network.dns_encrypted",
    "privacy.telemetry",
    "privacy.errors",
    "privacy.nonessential",
    "privacy.prompt_history",
    "privacy.subprocess_scrub",
    "privacy.otel_user_prompts",
    "privacy.otel_tool_content",
    "privacy.otel_tool_details",
    "privacy.otel_raw_api",
    "privacy.local_device_id",
    "privacy.telemetry_cache",
    "privacy.browser_fingerprint",
})

_ACTION_ORDER = ("must_fix", "optional_consistency", "leave_alone")

# Status order for report tables: fail first (must fix), then pass, then
# warning, then unknown (user preference).
_STATUS_ORDER = {"fail": 0, "pass": 1, "warning": 2, "unknown": 3}


def sort_checks(checks: Iterable[Any]) -> List[Any]:
    """Sort checks by status: fail → pass → warning → unknown (stable otherwise)."""
    return sorted(
        checks,
        key=lambda c: _STATUS_ORDER.get(
            str(_field(c, "status", "") or "").strip().lower(), 4
        ),
    )

# Chinese labels for the severity column (fallback: raw value).
_SEVERITY_ZH = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
    "unknown": "未知",
}

# Technical section titles stay stable for agents; plain titles are added beside them.
_ACTION_TITLES = {
    "must_fix": "Must fix",
    "optional_consistency": "Optional consistency",
    "leave_alone": "Leave alone",
}
_ACTION_PLAIN = {
    "zh": {
        "must_fix": "必须处理（确认有问题，建议尽快改）",
        "optional_consistency": "可选一致性（不是泄漏，看你要不要统一）",
        "leave_alone": "保持不动（正常或无需处理）",
    },
    "en": {
        "must_fix": "Must fix (confirmed problem — change soon)",
        "optional_consistency": "Optional consistency (not a leak — tidy if you want)",
        "leave_alone": "Leave alone (healthy or no action needed)",
    },
}
_STATUS_PLAIN = {
    "zh": {
        "pass": "通过",
        "fail": "失败",
        "warning": "警告",
        "unknown": "未知/未验证",
        "skipped": "已跳过",
        "error": "出错",
    },
    "en": {
        "pass": "pass",
        "fail": "fail",
        "warning": "warning",
        "unknown": "unknown / not verified",
        "skipped": "skipped",
        "error": "error",
    },
}
_SEVERITY_MUST = frozenset({"medium", "high", "critical"})

# Plain-language meaning of each check id (what it is about — not the result).
_CHECK_PLAIN = {
    "zh": {
        "privacy.telemetry": "Claude 会不会把使用数据（埋点）发回去",
        "privacy.errors": "Claude 会不会自动上报错误日志",
        "privacy.nonessential": "是否关掉非必要的后台联网",
        "privacy.prompt_history": "是否少把对话记录长期留在本地（补充项，未配置不等于坏）",
        "privacy.subprocess_scrub": "子进程会不会继承敏感环境变量（补充项）",
        "privacy.otel_user_prompts": "监控系统会不会记下你的提问内容（补充项）",
        "privacy.otel_tool_content": "监控系统会不会记下工具调用内容（补充项）",
        "privacy.otel_tool_details": "监控系统会不会记下工具细节（补充项）",
        "privacy.otel_raw_api": "监控系统会不会记下原始 API 正文（补充项）",
        "privacy.local_device_id": "本机是否残留 Claude/设备身份相关目录（只看有没有，不读 ID）",
        "privacy.telemetry_cache": "本机是否有遥测/缓存目录可清理（本地卫生，不是解封）",
        "privacy.browser_fingerprint": "浏览器 WebRTC/指纹姿态：只建议正规隐私设置，不建议伪装浏览器",
        "network.service": "代理软件（Mihomo）是否在正常运行、端口是否在听",
        "network.teredo": "系统有没有开可能绕过代理的 IPv6 隧道（Teredo）",
        "network.ipv6_binding": "网卡 IPv6 会不会从物理网络直接出去",
        "network.dns_physical_resolver": "宽带/路由器 DNS 是否还配在物理网卡上（有 fake-IP 时通常无害）",
        "network.env_proxy": "系统/终端里有没有手动设置代理环境变量",
        "network.system_proxy": "Windows 系统代理是否打开，并指向本机代理端口",
        "network.other_proxy_clients": "有没有别的代理软件同时在跑、可能打架",
        "system.locale": "系统语言/地区设置是否互相一致",
        "system.timezone": "系统时区是什么",
        "browser.webrtc.chrome": "Chrome 有没有限制 WebRTC 暴露真实地址（策略层，非实测）",
        "browser.webrtc.edge": "Edge 有没有限制 WebRTC 暴露真实地址（策略层，非实测）",
        "browser.webrtc.firefox": "Firefox 有没有限制 WebRTC 暴露真实地址（策略层，非实测）",
        "network.mode": "代理是否工作在「规则模式」（按规则分流）",
        "network.allow_lan": "是否禁止局域网其它设备蹭你的代理端口",
        "network.tun": "是否开启虚拟网卡全隧道（TUN）；关着也可能只是系统代理模式",
        "network.strict_route": "严格路由：尽量让流量按隧道走、减少漏网",
        "network.dns": "代理是否接管 DNS 查询",
        "network.dns_mode": "是否使用 fake-IP（用假 IP 先占位，再走代理解析）",
        "network.dns_hijack": "是否劫持 53 端口 DNS，减少查询绕过代理",
        "network.dns_respect_rules": "DNS 是否也遵守分流规则",
        "network.dns_ipv6": "DNS 的 IPv6 开关是否和整体 IPv6 策略一致",
        "network.dns_encrypted": "上游 DNS 是否使用加密（如 DoH）",
        "network.tun_stack": "TUN 使用的网络栈类型（如 gvisor），本身不代表泄漏",
        "network.policy_group": "节点是否固定选择，而不是自动测速乱跳",
        "network.mihomo": "有没有读到 Mihomo/Clash 配置",
        "network.dns.consistency": "在线时观察 DNS 能否解析（不能单独证明泄漏）",
        "network.ip_reputation": "在线时出口 IP 的国家/运营商类标签（第三方看法，不是判决）",
        "network.cross_site.routing": "在线时多个网站看到的出口是否一致",
        "network.egress.probe_error": "在线探测没跑成",
        "network.dns.egress_consistency": "在线实测：DNS 解析出口与 HTTP 出口是否一致（只读检测，不自动改）",
        "network.tls.fingerprint": "在线实测本机 TLS 客户端指纹（JA3/JA4，只读检测，不给伪装建议）",
        "network.anthropic_baseurl": "ANTHROPIC_BASE_URL 指向官方还是第三方中转（含公开风控黑名单情报比对）",
        "network.anthropic_baseurl_tcp": "在线实测：拨测 ANTHROPIC_BASE_URL 指向的中转服务器 443 端口是否存活（只读，不经过本地代理）",
    },
    "en": {
        "privacy.telemetry": "Whether Claude metrics telemetry is disabled",
        "privacy.errors": "Whether Claude error reporting is disabled",
        "privacy.nonessential": "Whether non-essential Claude background traffic is disabled",
        "privacy.prompt_history": "Optional: reduce local prompt-history persistence",
        "privacy.subprocess_scrub": "Optional: scrub secrets from subprocess environments",
        "privacy.otel_user_prompts": "Optional: whether OpenTelemetry logs user prompts",
        "privacy.otel_tool_content": "Optional: whether OpenTelemetry logs tool content",
        "privacy.otel_tool_details": "Optional: whether OpenTelemetry logs tool details",
        "privacy.otel_raw_api": "Optional: whether OpenTelemetry logs raw API bodies",
        "privacy.local_device_id": "Whether local Claude/device identity paths exist (presence only)",
        "privacy.telemetry_cache": "Whether local telemetry/cache dirs exist (hygiene, not unban)",
        "privacy.browser_fingerprint": "Browser WebRTC/fingerprint posture; policy hardening only, no anti-detect",
        "network.service": "Whether the Mihomo proxy process/service and port are up",
        "network.teredo": "Whether Teredo (an IPv6 tunnel that can bypass the proxy) is off",
        "network.ipv6_binding": "Whether physical NICs expose IPv6 that could bypass the tunnel",
        "network.dns_physical_resolver": "Whether ISP DNS is still configured on physical adapters",
        "network.env_proxy": "Whether HTTP(S)_PROXY environment variables are set",
        "network.system_proxy": "Whether Windows system proxy points at the local proxy port",
        "network.other_proxy_clients": "Whether other proxy apps are also running",
        "system.locale": "Whether Windows language/locale settings agree with each other",
        "system.timezone": "What timezone Windows is using",
        "browser.webrtc.chrome": "Chrome managed WebRTC policy only (not a live WebRTC test)",
        "browser.webrtc.edge": "Edge managed WebRTC policy only (not a live WebRTC test)",
        "browser.webrtc.firefox": "Firefox managed WebRTC policy only (not a live WebRTC test)",
        "network.mode": "Whether the proxy is in rule mode",
        "network.allow_lan": "Whether LAN devices are blocked from using your proxy port",
        "network.tun": "Whether full-tunnel TUN is on; off may mean system-proxy mode on purpose",
        "network.strict_route": "Strict routing to reduce traffic leaking off the tunnel",
        "network.dns": "Whether the proxy handles DNS lookups",
        "network.dns_mode": "Whether fake-IP DNS mode is enabled",
        "network.dns_hijack": "Whether port-53 DNS is hijacked into the proxy",
        "network.dns_respect_rules": "Whether DNS follows the same routing rules",
        "network.dns_ipv6": "Whether DNS IPv6 matches the IPv6 routing toggle",
        "network.dns_encrypted": "Whether upstream DNS uses encryption (e.g. DoH)",
        "network.tun_stack": "Which TUN stack is used (informational)",
        "network.policy_group": "Whether the node is pinned instead of auto-switching",
        "network.mihomo": "Whether Mihomo/Clash config was available",
        "network.dns.consistency": "Online DNS resolve observation (not leak proof alone)",
        "network.ip_reputation": "Online exit IP labels from third parties (opinion, not verdict)",
        "network.cross_site.routing": "Online check that several sites see a consistent exit",
        "network.egress.probe_error": "Online probes failed to run",
        "network.dns.egress_consistency": "Online: whether DNS resolution egress matches HTTP egress (read-only)",
        "network.tls.fingerprint": "Online TLS client fingerprint (JA3/JA4, read-only; no spoofing advice)",
        "network.anthropic_baseurl": "Whether ANTHROPIC_BASE_URL points at the official endpoint or a third-party relay (public risk-intel compare)",
        "network.anthropic_baseurl_tcp": "Online: TCP-443 reachability probe of the configured ANTHROPIC_BASE_URL host (read-only, direct dial, no local proxy)",
    },
}

_GLOSSARY = {
    "zh": [
        ("pass / 通过", "这项看起来正常。"),
        ("fail / 失败", "确认有问题，应处理。"),
        ("warning / 警告", "有风险或不一致，需要你看一眼。"),
        ("unknown / 未知", "证据不够，不能当成「安全」也不能当成「泄漏」。"),
        ("Must fix / 必须处理", "已确认的问题或高风险项。"),
        ("Optional consistency / 可选一致性", "不影响「有没有漏」，只是风格/习惯是否统一。"),
        ("Leave alone / 保持不动", "正常，或改了也没好处。"),
        ("Mihomo / Clash", "常见代理核心/客户端（如 Clash Verge 用的引擎）。"),
        ("系统代理 (system proxy)", "让软件走系统里填的代理地址（通常是 127.0.0.1:端口）。"),
        ("TUN / 全隧道", "虚拟网卡模式，更多流量强制进代理；比「仅系统代理」覆盖面更大。"),
        ("fake-IP", "DNS 先返回假 IP，真正访问时再走代理解析，便于接管查询。"),
        ("DNS 劫持 (port 53)", "把系统 DNS 查询拦到代理里，减少「查网站直接问宽带运营商」。"),
        ("DoH / 加密 DNS", "DNS 查询加密传输，减少被中间人偷看域名。"),
        ("JA3 / JA4", "两种公开的 TLS 客户端指纹算法；本工具只读计算本机指纹供观察，不给伪装/拟合建议。"),
        ("strict-route", "严格路由，减少流量从旁路溜走。"),
        ("Teredo", "一种 IPv6 隧道，有时会绕过你的代理，一般建议关掉。"),
        ("WebRTC", "浏览器实时通讯技术；配置不当可能暴露真实网络地址。本工具默认只看策略，不做网页实测。"),
        ("策略组 / policy group", "代理里选节点的分组；固定选择比自动测速乱跳更稳。"),
        ("not_configured", "这项开关根本没配，不等于已经泄漏。"),
    ],
    "en": [
        ("pass", "Looks healthy for this check."),
        ("fail", "Confirmed problem — act on it."),
        ("warning", "Risk or mismatch — review it."),
        ("unknown", "Not enough evidence; neither safe nor a proven leak."),
        ("Must fix", "Confirmed issues or high-risk items."),
        ("Optional consistency", "Not a leak; tidy only if you want consistency."),
        ("Leave alone", "Fine as-is, or changing it does not help."),
        ("Mihomo / Clash", "Common proxy engine/client stack."),
        ("System proxy", "Apps use the OS proxy address (usually 127.0.0.1:port)."),
        ("TUN", "Virtual-adapter full-tunnel mode; broader capture than system proxy alone."),
        ("fake-IP", "DNS returns placeholder IPs so lookups can be steered through the proxy."),
        ("DNS hijack (port 53)", "Forces DNS queries into the proxy path."),
        ("DoH", "Encrypted DNS so names are harder to snoop on the wire."),
        ("JA3 / JA4", "Public TLS client fingerprinting algorithms; this tool only computes your local fingerprint read-only, with no spoofing advice."),
        ("strict-route", "Tightens routing so fewer packets bypass the tunnel."),
        ("Teredo", "An IPv6 transition tunnel that can bypass the proxy; usually keep off."),
        ("WebRTC", "Browser realtime API; bad settings can expose real addresses. This tool only reads policy by default."),
        ("Policy group", "How nodes are chosen; fixed manual selection is stabler than auto URL-test."),
        ("not_configured", "The optional control is absent — not proof of a leak."),
    ],
}


def _field(check: Any, name: str, default: Any = None) -> Any:
    if isinstance(check, Mapping):
        return check.get(name, default)
    return getattr(check, name, default)


def _norm_lang(lang: Optional[str]) -> str:
    value = (lang or "zh").strip().lower()
    if value in ("en", "english"):
        return "en"
    return "zh"


# ---------------------------------------------------------------------------
# zh localization for check detail (explanation) + recommendation cells
# Phrase map + regex fallbacks; technical tokens (TunEnabled, keys) kept.
# ---------------------------------------------------------------------------

# Longer / more specific phrases first (applied left-to-right after sort by len).
_DETAIL_PHRASE_MAP: Tuple[Tuple[str, str], ...] = (
    (
        "System-proxy mode may be intentional; confirm the intended mode rather than treating TUN-off as an automatic failure.",
        "系统代理模式可能是有意为之；请确认目标模式，不要把「未开 TUN」自动当成失败。",
    ),
    (
        "the stack choice alone does not establish a routing leak.",
        "仅凭协议栈选择本身不能认定存在路由泄漏。",
    ),
    (
        "WebRTC runtime behavior was not verified; browser settings alone do not prove a leak. Policy presence is informational only.",
        "未验证 WebRTC 运行时行为；仅凭浏览器设置不能证明泄漏。策略是否存在仅供参考。",
    ),
    (
        "A restrictive WebRTC policy is configured (policy-layer signal only; not a live page WebRTC test).",
        "已配置较严格的 WebRTC 策略（仅策略层信号；不是网页实测）。",
    ),
    (
        "Browser WebRTC runtime was not fully verified, or restrictive policy was not observed on all installed browsers.",
        "未完整验证浏览器 WebRTC 运行时，或并非所有已安装浏览器都观察到限制性策略。",
    ),
    (
        "Installed browsers show restrictive WebRTC policy signals (policy layer only).",
        "已安装浏览器显示限制性 WebRTC 策略信号（仅策略层）。",
    ),
    (
        "Local Claude-related paths are present (presence only; IDs are not read). This does not prove the account or device is marked server-side.",
        "存在本机 Claude 相关路径（只看有无；不读取 ID）。这不能证明账号/设备已被服务端标记。",
    ),
    (
        "Local telemetry/cache-related paths under Claude home are present (sizes only; contents not read).",
        "Claude 主目录下存在遥测/缓存相关路径（仅大小；不读内容）。",
    ),
    (
        "No common local Claude device-id/home artifacts were observed.",
        "未观察到常见的本机 Claude 设备 ID/主目录残留。",
    ),
    (
        "No common local telemetry/cache artifact paths were observed.",
        "未观察到常见的本机遥测/缓存残留路径。",
    ),
    (
        "System proxy is enabled and points to loopback.",
        "系统代理已开启且指向回环地址。",
    ),
    (
        "System proxy settings are static configuration only; runtime routing was not verified.",
        "系统代理仅为静态配置；运行时路由未验证。",
    ),
    (
        "System proxy is enabled but does not point to loopback; confirm the target is intentional.",
        "系统代理已开启但未指向回环；请确认目标是否有意。",
    ),
    (
        "System proxy points to loopback but WinHTTP proxy is enabled and does not point to loopback; some apps may bypass the local client.",
        "系统代理指向回环，但 WinHTTP 代理已开启且未指向回环；部分应用可能绕过本地客户端。",
    ),
    (
        "System proxy is loopback-enabled while PAC/WPAD auto-config is active;",
        "系统代理已指向回环，同时 PAC/WPAD 自动配置处于活动状态；",
    ),
    (
        "Physical adapter DNS resolver(s) are configured, but fake-IP plus port-53",
        "物理网卡上配置了 DNS 解析器，但 fake-IP 加上 53 端口",
    ),
    (
        "No physical-ISP IPv4 resolver observed; tunnel or loopback resolvers only.",
        "未观察到物理宽带 IPv4 解析器；仅有隧道或回环解析器。",
    ),
    (
        "Proxy auto-configuration flags were not collected.",
        "未采集到代理自动配置相关标志。",
    ),
    (
        "Culture/UICulture/SystemLocale differ.",
        "Culture/UICulture/SystemLocale 不一致。",
    ),
    (
        "Locale is consistent",
        "区域设置一致",
    ),
    (
        "Geo stack is partial (timezone and/or culture incomplete).",
        "地理栈不完整（时区和/或区域字段缺失）。",
    ),
    (
        "Geo stack fields (TimeZone, Culture/UICulture) were not available.",
        "地理栈字段（TimeZone、Culture/UICulture）不可用。",
    ),
    (
        "Offline only — not tied to exit IP.",
        "仅离线信息 — 与出口 IP 无关。",
    ),
    (
        "Offline informational only.",
        "仅离线信息，供参考。",
    ),
    (
        "already differ (see system.locale).",
        "已不一致（见 system.locale）。",
    ),
    (
        "culture/UI culture present but locale fields",
        "已有 culture/UI culture，但区域字段",
    ),
    (
        "and culture/UI culture are present",
        "且 culture/UI culture 存在",
    ),
    (
        "requires manual confirmation.",
        "需要人工确认。",
    ),
    (
        "was not verified.",
        "未得到验证。",
    ),
    (
        "was not observed.",
        "未被观察到。",
    ),
    (
        "were not observed.",
        "未被观察到。",
    ),
    (
        "was not collected.",
        "未采集。",
    ),
    (
        "were not collected.",
        "未采集。",
    ),
    (
        "was not available.",
        "不可用。",
    ),
    (
        "were not available.",
        "不可用。",
    ),
    (
        "is active",
        "处于活动状态",
    ),
    (
        "are active",
        "处于活动状态",
    ),
    (
        "Physical adapter",
        "物理网卡",
    ),
    (
        "Physical-ISP DNS resolver",
        "物理宽带 DNS 解析器",
    ),
    (
        "System proxy",
        "系统代理",
    ),
    (
        "system proxy loopback",
        "系统代理回环",
    ),
    (
        "alongside a loopback system proxy",
        "与回环系统代理并存",
    ),
    (
        "loopback system proxy",
        "回环系统代理",
    ),
    (
        "points to loopback",
        "指向回环",
    ),
    (
        "point to loopback",
        "指向回环",
    ),
    (
        "WinHTTP loopback",
        "WinHTTP 回环",
    ),
    (
        "policy layer only",
        "仅策略层",
    ),
    (
        "policy-layer signal only",
        "仅策略层信号",
    ),
    (
        "not a live page WebRTC test",
        "不是网页 WebRTC 实测",
    ),
    (
        "presence only; IDs are not read",
        "只看有无；不读取 ID",
    ),
    (
        "sizes only; contents not read",
        "仅大小；不读内容",
    ),
    (
        "Encrypted upstream scheme(s) present:",
        "已发现加密上游方案：",
    ),
    (
        "DNS upstream scheme(s) present:",
        "已发现 DNS 上游方案：",
    ),
    (
        "Automatic selector type(s) present:",
        "存在自动选择器类型：",
    ),
    (
        "Policy selection is fixed",
        "策略选择已固定",
    ),
    (
        "with no automatic selectors.",
        "且无自动选择器。",
    ),
    (
        "Policy selection could not be resolved from the local controller.",
        "无法从本地控制器解析策略选择。",
    ),
    (
        "TimeZone is ",
        "时区为 ",
    ),
    (
        "TimeZone (",
        "时区（",
    ),
    (
        "Observed ",
        "观察到 ",
    ),
    (
        "[not_configured] ",
        "[未配置] ",
    ),
)

_RECOMMENDATION_PHRASE_MAP: Tuple[Tuple[str, str], ...] = (
    (
        "OPTIONAL RECOMMENDATION ONLY — never auto-applied by this tool or its remediation scripts:",
        "【仅可选建议 — 本工具及其修复脚本绝不会自动执行】：",
    ),
    (
        "OPTIONAL RECOMMENDATION ONLY — never auto-applied:",
        "【仅可选建议 — 绝不会自动执行】：",
    ),
    (
        "Optional recommendation only (never auto-applied):",
        "【仅可选建议（绝不会自动执行）】：",
    ),
    (
        "Optional recommendation only (never auto-applied)",
        "仅可选建议（绝不会自动执行）",
    ),
    (
        "OPTIONAL RECOMMENDATION ONLY",
        "仅可选建议",
    ),
    (
        "never auto-applied by this tool or its remediation scripts",
        "本工具及其修复脚本绝不会自动执行",
    ),
    (
        "never auto-applied",
        "绝不会自动执行",
    ),
    (
        "never auto-changes fingerprints",
        "绝不会自动改指纹",
    ),
    (
        "never changes browser settings automatically",
        "绝不会自动改浏览器设置",
    ),
    (
        "never applied by scripts",
        "脚本绝不会代为执行",
    ),
    (
        "Scripts never reset device IDs for you.",
        "脚本绝不会替你重置设备 ID。",
    ),
    (
        "Scripts never delete caches for you.",
        "脚本绝不会替你删除缓存。",
    ),
    (
        "Claude Shield will not change DNS, routes, TUN, timezone, or fingerprints for you.",
        "Claude Shield 不会替你改 DNS、路由、TUN、时区或指纹。",
    ),
    (
        "Confirm the setting in the active proxy client before changing it.",
        "更改前请先在当前代理客户端中确认该设置。",
    ),
    (
        "Only enable TUN if it matches the intended routing mode; system-proxy alone is not a leak.",
        "仅在符合目标路由模式时再开启 TUN；仅用系统代理本身不算泄漏。",
    ),
    (
        "Enable respect-rules so DNS resolution follows rule routing instead of bypassing the proxy.",
        "启用 respect-rules，使 DNS 解析跟随规则路由，而不是绕过代理。",
    ),
    (
        "Confirm whether IPv6 DNS resolution is intended given the IPv6 routing toggle.",
        "请结合 IPv6 路由开关，确认是否有意开启 IPv6 DNS 解析。",
    ),
    (
        "Verify the active DNS path before changing upstreams.",
        "更改上游前请先核实当前实际 DNS 路径。",
    ),
    (
        "Keep the stack already proven on this machine unless a controlled test shows a problem.",
        "除非受控测试发现问题，否则保持本机已验证可用的协议栈。",
    ),
    (
        "Optional consistency only: change values only when they reflect genuine long-term use.",
        "仅可选一致性：只有在反映真实长期使用习惯时才改这些值。",
    ),
    (
        "Optional consistency only: keep timezone truthful for the user's real location.",
        "仅可选一致性：时区应与用户真实所在地一致。",
    ),
    (
        "Optional consistency only: timezone was not reported by the collector.",
        "仅可选一致性：采集器未报告时区。",
    ),
    (
        "Optional consistency only:",
        "仅可选一致性：",
    ),
    (
        "Keep timezone and language truthful for real use; do not auto-follow a proxy/node country. "
        "Optional alignment only — consider confirming values reflect genuine long-term location and language.",
        "时区与语言应反映真实使用；不要自动跟随代理/节点所在国家。"
        "仅可选对齐 — 请确认数值是否反映真实长期所在地与语言。",
    ),
    (
        "Keep timezone and language truthful for real use; do not auto-follow a proxy/node country.",
        "时区与语言应反映真实使用；不要自动跟随代理/节点所在国家。",
    ),
    (
        "Optional alignment only — consider confirming values reflect genuine long-term location and language.",
        "仅可选对齐 — 请确认数值是否反映真实长期所在地与语言。",
    ),
    (
        "Set DISABLE_TELEMETRY=1 only if that documented opt-out matches the user's privacy preference.",
        "仅当该文档化退出项符合用户隐私偏好时，再设置 DISABLE_TELEMETRY=1。",
    ),
    (
        "Set DISABLE_ERROR_REPORTING=1 only if that documented opt-out matches the user's privacy preference.",
        "仅当该文档化退出项符合用户隐私偏好时，再设置 DISABLE_ERROR_REPORTING=1。",
    ),
    (
        "Set CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 only if that documented opt-out matches the user's privacy preference.",
        "仅当该文档化退出项符合用户隐私偏好时，再设置 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1。",
    ),
    (
        "only if that documented opt-out matches the user's privacy preference.",
        "仅当该文档化退出项符合用户隐私偏好时再设置。",
    ),
    (
        "No local device-id reset recommended from this scan. (Any future reset would remain optional and manual.)",
        "本次扫描不建议重置本机设备 ID。（若将来要重置，仍须可选且手动。）",
    ),
    (
        "No local cache clear recommended from this scan. (Any future clear would remain optional and manual.)",
        "本次扫描不建议清理本机缓存。（若将来要清理，仍须可选且手动。）",
    ),
    (
        "Consider re-running the Windows collector if PAC/WPAD posture matters.",
        "若关心 PAC/WPAD 姿态，可考虑重新运行 Windows 采集器。",
    ),
    (
        "Consider aligning WinHTTP with the loopback system proxy, or confirm WinHTTP direct access is intended.",
        "可考虑将 WinHTTP 与回环系统代理对齐，或确认 WinHTTP 直连是有意为之。",
    ),
    (
        "Consider re-collecting System proxy fields if multi-layer consistency matters.",
        "若关心多层代理一致性，可考虑重新采集系统代理字段。",
    ),
    (
        "OPTIONAL only: keep policy-based WebRTC restrictions.",
        "【仅可选】：保持基于策略的 WebRTC 限制。",
    ),
    (
        "Do not use anti-detect browsers or spoof fingerprints — this tool never auto-changes fingerprints.",
        "不要使用反检测浏览器或伪造指纹 — 本工具绝不会自动改指纹。",
    ),
    (
        "Do not use anti-detect browsers or fabricated fingerprints",
        "不要使用反检测浏览器或伪造指纹",
    ),
    (
        "Do not use anti-detect stacks or fabricated fingerprints.",
        "不要使用反检测栈或伪造指纹。",
    ),
    (
        "Do not install anti-detect browsers or spoof fingerprints.",
        "不要安装反检测浏览器或伪造指纹。",
    ),
    (
        "Fingerprint spoof is recommend-only and never applied by scripts.",
        "指纹伪装仅为建议，脚本绝不会代为执行。",
    ),
    (
        "they do not clear server marks and are outside this product’s boundary.",
        "它们不能清除服务端标记，且超出本产品边界。",
    ),
    (
        "they do not clear server marks and are outside this product's boundary.",
        "它们不能清除服务端标记，且超出本产品边界。",
    ),
    (
        "Prefer a normal profile with proxy + WebRTC restrictions over spoofing stacks.",
        "优先使用「正常配置文件 + 代理 + WebRTC 限制」，而不是伪装栈。",
    ),
    (
        "tighten real browser WebRTC/privacy settings (policy or browser flags) if you want that posture.",
        "若需要该姿态，请收紧真实浏览器的 WebRTC/隐私设置（策略或浏览器标志）。",
    ),
    (
        "if you want less local address exposure, tighten real-browser WebRTC/privacy policy or flags.",
        "若希望减少本机地址暴露，请收紧真实浏览器的 WebRTC/隐私策略或标志。",
    ),
    (
        "Optional policy only: keep the restrictive WebRTC policy if it matches your privacy preference.",
        "【仅可选策略】：若符合隐私偏好，可保持限制性 WebRTC 策略。",
    ),
    (
        "This tool never changes browser settings automatically.",
        "本工具绝不会自动改浏览器设置。",
    ),
    (
        "you may choose to reset local device-id/home artifacts if you want a fresh *local* identity.",
        "若希望刷新*本机*身份，可选择重置本机 device-id/主目录残留。",
    ),
    (
        "This cannot clear Anthropic server-side device/account marks, cannot unban, and is not required for a healthy proxy audit.",
        "这不能清除 Anthropic 服务端设备/账号标记，不能解封，也不是健康代理审计的必要条件。",
    ),
    (
        "Prefer backup-then-delete of known local paths; do not use fingerprint-spoofing or anti-detect tools.",
        "优先对已知本机路径「先备份再删除」；不要使用指纹伪装或反检测工具。",
    ),
    (
        "clear local telemetry/cache directories after backup if you want less residual local data.",
        "若希望减少本机残留数据，可在备份后清理本地遥测/缓存目录。",
    ),
    (
        "Disabling DISABLE_TELEMETRY / related env vars matters more for future collection.",
        "对未来采集而言，设置 DISABLE_TELEMETRY / 相关环境变量更重要。",
    ),
    (
        "Clearing cache does not remove server-side history or device marks and is not an “environment wipe” or unban step.",
        "清缓存不会删除服务端历史或设备标记，也不是「洗环境」或解封步骤。",
    ),
    (
        "Clearing cache does not remove server-side history or device marks and is not an \"environment wipe\" or unban step.",
        "清缓存不会删除服务端历史或设备标记，也不是「洗环境」或解封步骤。",
    ),
    (
        "System proxy",
        "系统代理",
    ),
    (
        "loopback",
        "回环",
    ),
    (
        "Physical adapter",
        "物理网卡",
    ),
)

# Regex patterns applied after phrase map (detail + recommendation shared patterns).
_SHARED_REGEX: Tuple[Tuple[str, str], ...] = (
    # Observed Key=value / Observed Key='value'
    (
        r"\bObserved\s+([A-Za-z][A-Za-z0-9_]*)\s*=\s*",
        r"观察到 \1=",
    ),
    (r"\bObserved\s+", "观察到 "),
    (r"\bwas not observed\b", "未被观察到"),
    (r"\bwere not observed\b", "未被观察到"),
    (r"\bwas not verified\b", "未得到验证"),
    (r"\bis active\b", "处于活动状态"),
    (r"\bare active\b", "处于活动状态"),
    (r"\bSystem proxy\b", "系统代理"),
    (r"\bsystem proxy\b", "系统代理"),
    (r"\bPhysical adapter\b", "物理网卡"),
    (r"\bPhysical-ISP\b", "物理宽带"),
    (r"\bOPTIONAL RECOMMENDATION ONLY\b", "仅可选建议"),
    (r"\bnever auto-applied\b", "绝不会自动执行"),
    (r"\bnever auto-applied by this tool or its remediation scripts\b", "本工具及其修复脚本绝不会自动执行"),
    (r"\brequires manual confirmation\b", "需要人工确认"),
    (r"\bSystem-proxy mode may be intentional\b", "系统代理模式可能是有意为之"),
    (r"\bpoints? to loopback\b", "指向回环"),
    (r"\bloopback\b", "回环"),
    (r"\[not_configured\]\s*", "[未配置] "),
    (r"\bTimeZone is\b", "时区为"),
    (r"\bnot a leak\b", "不算泄漏"),
    (r"\bmanual confirmation\b", "人工确认"),
)


def _apply_phrase_map(text: str, phrases: Tuple[Tuple[str, str], ...]) -> str:
    """Apply longest-first literal replacements (case-sensitive for technical fidelity)."""
    if not text:
        return text
    # Sort by English length descending so longer phrases win.
    ordered = sorted(phrases, key=lambda p: len(p[0]), reverse=True)
    out = text
    for eng, zhs in ordered:
        if eng and eng in out:
            out = out.replace(eng, zhs)
    return out


def _apply_regex_map(text: str, patterns: Tuple[Tuple[str, str], ...]) -> str:
    out = text
    for pattern, repl in patterns:
        out = re.sub(pattern, repl, out)
    return out


def translate_detail(text: str, lang: str = "zh") -> str:
    """Localize a check explanation/detail string.

    When ``lang`` is English, return unchanged. For Chinese, apply phrase map
    then regex fallbacks. Mostly-technical English leftovers are kept as-is
    (no extra prefix).
    """
    if text is None:
        return ""
    raw = str(text)
    if not raw.strip():
        return raw
    if _norm_lang(lang) != "zh":
        return raw
    out = _apply_phrase_map(raw, _DETAIL_PHRASE_MAP)
    out = _apply_regex_map(out, _SHARED_REGEX)
    return out


def translate_recommendation(text: str, lang: str = "zh") -> str:
    """Localize a check recommendation string (same rules as translate_detail)."""
    if text is None:
        return ""
    raw = str(text)
    if not raw.strip():
        return raw
    if _norm_lang(lang) != "zh":
        return raw
    out = _apply_phrase_map(raw, _RECOMMENDATION_PHRASE_MAP)
    out = _apply_regex_map(out, _SHARED_REGEX)
    # Light second pass on residual detail-style fragments inside recommendations.
    out = _apply_phrase_map(out, _DETAIL_PHRASE_MAP)
    return out


def plain_status(status: str, lang: str = "zh") -> str:
    lang = _norm_lang(lang)
    key = str(status or "").lower()
    return _STATUS_PLAIN.get(lang, _STATUS_PLAIN["zh"]).get(key, str(status or ""))


def plain_action(action: str, lang: str = "zh") -> str:
    lang = _norm_lang(lang)
    return _ACTION_PLAIN.get(lang, _ACTION_PLAIN["zh"]).get(action, action)


def plain_check(check_id: str, lang: str = "zh") -> str:
    """Return a one-line plain explanation of what this check means.

    Known ids use the map; unknown ids fall back by prefix so every row still
    has a de-jargon 说明/meaning line (never empty).
    """
    lang = _norm_lang(lang)
    table = _CHECK_PLAIN.get(lang, _CHECK_PLAIN["zh"])
    check_id = str(check_id or "").strip()
    if check_id in table:
        return table[check_id]

    # Dynamic / future-id prefix fallbacks (de-jargon, not raw status dumps)
    zh = lang == "zh"
    if check_id.startswith("network.egress.runtime_consistency"):
        return (
            "在线对比不同方式看到的出口是否一致"
            if zh
            else "Online: whether different runtimes see the same egress"
        )
    if check_id.startswith("network.egress."):
        return (
            "在线出口探测：本机实际出去的路径是否和预期一致"
            if zh
            else "Online egress probe: whether traffic leaves as expected"
        )
    if check_id.startswith("network.dns."):
        return (
            "DNS 相关在线/配置检查（解析路径是否合理）"
            if zh
            else "DNS-related online/config check (resolver path sanity)"
        )
    if check_id.startswith("network.cross_site."):
        return (
            "跨站在线对比：多个网站看到的出口是否一致"
            if zh
            else "Cross-site online check: whether several sites see the same exit"
        )
    if check_id.startswith("network.ip_"):
        return (
            "出口 IP 的第三方标签/声誉（看法，不是判决）"
            if zh
            else "Exit-IP third-party labels/reputation (opinion, not a verdict)"
        )
    if check_id.startswith("network."):
        return (
            "代理/网络配置项：路由、DNS、隧道或代理客户端状态"
            if zh
            else "Proxy/network setting: routing, DNS, tunnel, or client state"
        )
    if check_id.startswith("browser.webrtc."):
        return (
            "浏览器 WebRTC 策略（不是网页实测；仅可选建议）"
            if zh
            else "Browser WebRTC policy only (not a live page test; optional advice)"
        )
    if check_id.startswith("browser."):
        return (
            "浏览器相关策略/隐私姿态（只读建议，不改浏览器）"
            if zh
            else "Browser policy/privacy posture (read-only advice; no browser changes)"
        )
    if check_id.startswith("privacy."):
        return (
            "隐私相关设置或本地残留：只给可选建议，不会自动改"
            if zh
            else "Privacy setting or local residue: optional advice only, never auto-applied"
        )
    if check_id.startswith("system."):
        return (
            "系统语言/时区等本机设置是否自洽（一致性，不是泄漏判决）"
            if zh
            else "OS language/timezone consistency (consistency, not a leak verdict)"
        )
    if check_id.startswith("consistency."):
        return (
            "配置是否自洽：各项设置彼此是否对得上"
            if zh
            else "Configuration self-consistency: whether settings agree with each other"
        )
    # Generic future-id fallback — still plain language, never blank
    short = check_id.split(".")[-1].replace("_", " ") if check_id else "item"
    return (
        f"本项「{short}」的配置/证据自检（见详情；不是防封评分）"
        if zh
        else f"Config/evidence self-check for “{short}” (see detail; not an anti-ban score)"
    )


def status_reason(check: Any) -> str:
    """Return a short subtype tag for unknown/optional checks.

    Encoded in explanation as ``[not_configured] ...`` when applicable;
    otherwise empty. Does not alter the AuditCheck schema.
    """
    explanation = str(_field(check, "explanation", "") or "")
    stripped = explanation.lstrip()
    if stripped.startswith("[") and "]" in stripped:
        tag = stripped[1:stripped.index("]")]
        if tag:
            return tag
    confidence = str(_field(check, "confidence", "") or "")
    status = str(_field(check, "status", "") or "")
    if status == "unknown" and confidence == "unknown":
        check_id = str(_field(check, "id", "") or "")
        if check_id.startswith("privacy."):
            return "not_configured"
    return ""


def classify_action(check: Any) -> str:
    """Classify a check into must_fix | optional_consistency | leave_alone."""
    status = str(_field(check, "status", "") or "")
    severity = str(_field(check, "severity", "info") or "info")
    check_id = str(_field(check, "id", "") or "")
    explanation = str(_field(check, "explanation", "") or "")
    reason = status_reason(check)

    if status == "fail":
        return "must_fix"
    if status == "warning" and severity in _SEVERITY_MUST:
        return "must_fix"
    if status in ("fail", "warning") and check_id in _LEAKISH_IDS:
        return "must_fix"

    if check_id in ("system.locale", "system.timezone"):
        if status == "pass":
            return "leave_alone"
        return "optional_consistency"

    if check_id == "network.tun" and status in ("unknown", "warning"):
        return "optional_consistency"

    # Folded supplemental privacy (OTEL / prompt_history / scrub) — leave alone
    if "[folded_optional]" in explanation:
        return "leave_alone"

    if reason == "not_configured" or "[not_configured]" in explanation:
        return "optional_consistency"

    if check_id in _OPTIONAL_IDS and status in ("unknown", "warning"):
        return "optional_consistency"

    if status == "pass":
        return "leave_alone"

    if status == "warning" and severity in ("low", "info"):
        if check_id not in _LEAKISH_IDS:
            return "optional_consistency"

    if status in ("unknown", "skipped"):
        return "leave_alone"

    return "leave_alone"


def group_checks(checks: Iterable[Any]) -> Dict[str, List[Any]]:
    """Group checks by classify_action() result."""
    groups: Dict[str, List[Any]] = {key: [] for key in _ACTION_ORDER}
    for check in checks:
        action = classify_action(check)
        if action not in groups:
            action = "leave_alone"
        groups[action].append(check)
    return groups



def score_checks(checks: Iterable[Any]) -> Dict[str, Any]:
    """Compute a 0-100 **configuration self-consistency** score.

    Measures how coherent the local audit findings are (must-fix vs optional
    consistency vs incomplete evidence). This is **not** “looks like country X”
    and **not** an anti-ban / stealth score.
    Starts at 100 and subtracts weighted penalties. Floor 0, ceiling 100.
    """
    checks = list(checks or [])
    score = 100
    breakdown = {
        "must_fix_penalty": 0,
        "optional_penalty": 0,
        "incomplete_penalty": 0,
        "must_fix": 0,
        "optional_consistency": 0,
        "leave_alone": 0,
    }
    deductions = []

    for check in checks:
        action = classify_action(check)
        status = str(_field(check, "status", "") or "").lower()
        severity = str(_field(check, "severity", "info") or "info").lower()
        check_id = str(_field(check, "id", "") or "")
        reason = status_reason(check)
        breakdown[action] = breakdown.get(action, 0) + 1

        penalty = 0
        if action == "must_fix":
            if status == "fail":
                penalty = 18
            elif status == "warning":
                penalty = 14
            else:
                penalty = 10
            if severity == "medium":
                penalty += 2
            elif severity == "high":
                penalty += 4
            elif severity == "critical":
                penalty += 6
            breakdown["must_fix_penalty"] += penalty
        elif action == "optional_consistency":
            if reason == "not_configured" or check_id.startswith("privacy.otel") or check_id in (
                "privacy.prompt_history",
                "privacy.subprocess_scrub",
            ):
                penalty = 1
            elif status == "warning":
                penalty = 3
            elif status == "unknown":
                penalty = 2
            else:
                penalty = 1
            breakdown["optional_penalty"] += penalty
        elif action == "leave_alone" and status == "unknown" and check_id in _LEAKISH_IDS:
            penalty = 1
            breakdown["incomplete_penalty"] += penalty

        if penalty:
            score -= penalty
            deductions.append({
                "id": check_id,
                "action": action,
                "status": status,
                "penalty": penalty,
            })

    score = max(0, min(100, int(score)))
    if score >= 90:
        grade, label_zh, label_en = "A", "配置较自洽", "Highly consistent"
    elif score >= 75:
        grade, label_zh, label_en = "B", "大体自洽", "Mostly consistent"
    elif score >= 60:
        grade, label_zh, label_en = "C", "一般自洽", "Partly consistent"
    else:
        grade, label_zh, label_en = "D", "自洽性偏弱", "Low consistency"

    return {
        "score": score,
        "max_score": 100,
        "grade": grade,
        "label_zh": label_zh,
        "label_en": label_en,
        "score_kind": "configuration_self_consistency",
        "breakdown": breakdown,
        "deductions": deductions,
    }


def _evidence_cell(check: Any) -> str:
    items = _field(check, "evidence", None) or []
    if not items:
        return "—"
    parts = []
    for item in items[:3]:
        if isinstance(item, Mapping):
            desc = item.get("description") or item.get("type") or ""
        else:
            desc = getattr(item, "description", None) or getattr(item, "type", "") or ""
        desc = str(desc).replace("|", "/").strip()
        if desc:
            parts.append(desc)
    return "; ".join(parts) if parts else "—"


def _md_escape_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").replace("|", "/")
    return text.strip() or "—"



def _intro_lines(lang: str) -> List[str]:
    if lang == "en":
        return [
            "Read-only results from this machine.",
            "The number below is a **configuration consistency score** (0–100): how well the observed settings line up with each other.",
            "",
        ]
    return [
        "以下是本机的只读检查结果。",
        "下方数字是 **配置自洽分**（0–100），表示各项设置彼此是否对得上，便于对照。",
        "",
    ]


def _footer_lines(lang: str) -> List[str]:
    """Soft recommend-only boundary: what this tool never auto-applies."""
    if lang == "en":
        return [
            "## How this tool helps you change settings",
            "",
            "It **personalizes manual steps** for the proxy client it detects (timezone vs exit, local hygiene, DNS / route / TUN / IPv6 / system proxy).",
            "",
            "It will **not auto-apply** any of the following (you confirm and change them yourself):",
            "",
            "- spoof browser / device **fingerprints** (only normal privacy hardening tips)",
            "- force **timezone** to follow the node (may *suggest* manual align)",
            "- wipe / “launder” the environment (may *suggest* local hygiene; not unban)",
            "- invent an **anti-ban** or stealth score disguise",
            "- change **DNS**, routes, TUN, IPv6 adapters, or system proxy for you (may *suggest* steps)",
            "",
            "_Any change still needs your explicit approval. Remediation scripts, when used, still default to documented privacy env vars only._",
            "",
        ]
    return [
        "## 本工具如何协助你改配置",
        "",
        "会根据你正在用的梯子**给出个性化手动步骤**（时区对齐出口、本地卫生、DNS / 路由 / TUN / IPv6 / 系统代理等）。",
        "",
        "**不会自动执行**下列操作（需你确认后自己改）：",
        "",
        "- 改指纹 / 伪装浏览器（仅建议正规隐私设置）",
        "- 时区跟随节点 / 出口（可建议，不代改）",
        "- 清环境洗白（可建议本机卫生，不解封）",
        "- 防封评分伪装（不做）",
        "- 改 DNS · 路由 · TUN · IPv6 或系统代理（可建议，不代改）",
        "",
        "_任何修改都需要你明确同意。修复脚本（若使用）默认仍只处理文档中的隐私环境变量。_",
        "",
    ]



def _glossary_lines(lang: str) -> List[str]:
    title = "## Glossary" if lang == "en" else "## 名词解释"
    lines = [title, ""]
    lines.append("| term | meaning |" if lang == "en" else "| 名词 | 含义 |")
    lines.append("| --- | --- |")
    for term, meaning in _GLOSSARY.get(lang, _GLOSSARY["zh"]):
        lines.append(
            "| {t} | {m} |".format(
                t=_md_escape_cell(term),
                m=_md_escape_cell(meaning),
            )
        )
    lines.append("")
    return lines


def _signal_label(check: Any) -> str:
    check_id = str(_field(check, "id", "") or "")
    check_title = str(_field(check, "title", "") or "").strip()
    if check_title and check_id and check_title != check_id:
        return f"{check_title} (`{check_id}`)"
    return check_title or check_id or "—"


def _row_cells(check: Any, lang: str) -> Dict[str, str]:
    check_id = str(_field(check, "id", "") or "")
    status = str(_field(check, "status", "") or "")
    action = classify_action(check)
    explanation = str(_field(check, "explanation", "") or "").strip()
    recommendation = str(_field(check, "recommendation", "") or "").strip()
    if explanation.startswith("[") and "]" in explanation:
        # strip tags like [not_configured] for cleaner table detail
        tag_end = explanation.index("]")
        rest = explanation[tag_end + 1 :].strip()
        if rest:
            explanation = rest
    # Localize detail + recommendation when lang=zh (en leaves source text).
    explanation = translate_detail(explanation, lang) if explanation else explanation
    recommendation = (
        translate_recommendation(recommendation, lang) if recommendation else recommendation
    )
    # Severity label mapping for the report's severity column.
    sev_raw = str(_field(check, "severity", "") or "").strip().lower()
    severity = _SEVERITY_ZH.get(sev_raw, sev_raw or "—") if lang == "zh" else (sev_raw or "—")
    return {
        "item": _signal_label(check),
        "status": f"{plain_status(status, lang)} ({status})" if status else "—",
        "severity": severity,
        "meaning": plain_check(check_id, lang),
        "detail": explanation or "—",
        "group": plain_action(action, lang),
        "action_key": action,
        "recommendation": recommendation,
    }


def format_report(
    checks: Sequence[Any],
    summary: Optional[Mapping[str, Any]] = None,
    lang: str = "zh",
    compact: bool = False,
    snapshot: Optional[Mapping[str, Any]] = None,
    intended_mode: Optional[str] = None,
    intended_region: Optional[str] = None,
    **_kwargs: Any,
) -> str:
    """Render checks as markdown tables for AI/chat display.

    Plain-language text lives in table columns (说明 / meaning). Plain meaning is a normal table column.

    Parameters
    ----------
    compact:
        When True, emit intro + score + Must fix + Optional consistency only
        (no full results table, no Leave alone section, no glossary). Footer stays short.
    """
    lang = _norm_lang(lang)
    checks = list(checks or [])
    lines: List[str] = ["# Claude Shield Audit Report", ""]
    lines.extend(_intro_lines(lang))

    groups = group_checks(checks)
    scored = score_checks(checks)
    if lang == "zh":
        lines.extend([
            "## 配置自洽分",
            "",
            "| 项目 | 值 |",
            "| --- | --- |",
            f"| 配置自洽分 | **{scored['score']}** / {scored['max_score']} |",
            f"| 等级 | {scored['grade']}（{scored['label_zh']}） |",
            f"| 必须处理扣分 | -{scored['breakdown']['must_fix_penalty']}（{scored['breakdown']['must_fix']} 项） |",
            f"| 可选一致性扣分 | -{scored['breakdown']['optional_penalty']}（{scored['breakdown']['optional_consistency']} 项） |",
            f"| 证据不足扣分 | -{scored['breakdown']['incomplete_penalty']} |",
            "",
            "_配置自洽分满分 100：看配置是否前后一致。必须处理扣分多，可选一致性扣分少；未配置的补充隐私项每项只扣 1 分。_",
            "",
        ])
    else:
        lines.extend([
            "## Consistency score",
            "",
            "| item | value |",
            "| --- | --- |",
            f"| consistency score | **{scored['score']}** / {scored['max_score']} |",
            f"| grade | {scored['grade']} ({scored['label_en']}) |",
            f"| must-fix penalty | -{scored['breakdown']['must_fix_penalty']} ({scored['breakdown']['must_fix']} items) |",
            f"| optional penalty | -{scored['breakdown']['optional_penalty']} ({scored['breakdown']['optional_consistency']} items) |",
            f"| incomplete evidence | -{scored['breakdown']['incomplete_penalty']} |",
            "",
            "_Consistency score out of 100: how aligned the settings are. "
            "Must-fix costs more than optional consistency; "
            "not_configured privacy add-ons cost 1 each._",
            "",
        ])

    # Full report includes the all-results table; compact skips it.
    if not compact:
        if lang == "zh":
            lines.extend(
                [
                    "## 全部结果",
                    "",
                    "| 检查项 | 状态 | 严重度 | 说明 | 建议 |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
        else:
            lines.extend(
                [
                    "## All results",
                    "",
                    "| check | status | severity | meaning | recommendation |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )

        for check in sort_checks(checks):
            row = _row_cells(check, lang)
            rec = row["recommendation"] if row["action_key"] != "leave_alone" else ""
            meaning = row["meaning"] + (f"<br>{row['detail']}" if row["detail"] and row["detail"] != "—" else "")
            lines.append(
                "| {item} | {status} | {severity} | {meaning} | {rec} |".format(
                    item=_md_escape_cell(row["item"]),
                    status=_md_escape_cell(row["status"]),
                    severity=_md_escape_cell(row["severity"]),
                    meaning=_md_escape_cell(meaning),
                    rec=_md_escape_cell(rec or "—"),
                )
            )
        lines.append("")

    section_titles = {
        "zh": {
            "must_fix": "## 必须处理",
            "optional_consistency": "## 可选一致性",
            "leave_alone": "## 保持不动",
        },
        "en": {
            "must_fix": "## Must fix",
            "optional_consistency": "## Optional consistency",
            "leave_alone": "## Leave alone",
        },
    }
    head = (
        (
            "| 检查项 | 状态 | 严重度 | 说明 | 建议 |",
            "| --- | --- | --- | --- | --- |",
        )
        if lang == "zh"
        else (
            "| check | status | severity | meaning | recommendation |",
            "| --- | --- | --- | --- | --- |",
        )
    )

    # compact: only must_fix + optional_consistency (skip leave_alone)
    section_keys = (
        ("must_fix", "optional_consistency")
        if compact
        else _ACTION_ORDER
    )

    for key in section_keys:
        lines.append(section_titles[lang][key])
        lines.append("")
        items = groups.get(key) or []
        if not items:
            lines.append("_无。_" if lang == "zh" else "_None._")
            lines.append("")
            continue
        lines.append(head[0])
        lines.append(head[1])
        for check in sort_checks(items):
            row = _row_cells(check, lang)
            rec = "—" if key == "leave_alone" else (row["recommendation"] or "—")
            meaning = row["meaning"] + (f"<br>{row['detail']}" if row["detail"] and row["detail"] != "—" else "")
            lines.append(
                "| {item} | {status} | {severity} | {meaning} | {rec} |".format(
                    item=_md_escape_cell(row["item"]),
                    status=_md_escape_cell(row["status"]),
                    severity=_md_escape_cell(row["severity"]),
                    meaning=_md_escape_cell(meaning),
                    rec=_md_escape_cell(rec),
                )
            )
        lines.append("")

    if not compact:
        lines.extend(_glossary_lines(lang))
        if lang == "zh":
            lines.append("_不确定就会标明。第三方评分和静态配置，都不能单独当成「泄漏证据」。_")
        else:
            lines.append(
                "_Uncertainty is stated explicitly. Reputation scores and static "
                "configuration alone are not proof of a leak._"
            )
        lines.append("")

    # Personalized proxy client + manual action guidance
    try:
        from .personalize import build_personal_guidance, format_personal_section

        _guide = build_personal_guidance(
            snapshot,
            checks,
            intended_mode=intended_mode,
            intended_region=intended_region,
            lang=lang,
            cli_agent=_kwargs.get("cli_agent"),
        )
        lines.append(format_personal_section(_guide, lang=lang))
    except Exception:
        pass

    lines.extend(_footer_lines(lang))
    return "\n".join(lines)


__all__ = [
    "classify_action",
    "format_report",
    "group_checks",
    "score_checks",
    "plain_action",
    "plain_check",
    "plain_status",
    "status_reason",
    "translate_detail",
    "translate_recommendation",
]
